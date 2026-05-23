import json
from collections import Counter
from urllib.parse import urlencode

import structlog
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.mail import EmailMessage
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from main.forms import UserRegistrationForm, PcapUploadForm
from trafficlens_core import analyze_pcap_bytes
from .models import PcapFile

log = structlog.get_logger(__name__)

# ── Protocol colour map (shared with JS CHART_COLORS order) ───────────────────

_PROTO_COLORS = {
    'TCP': '#2563eb', 'UDP': '#7c3aed', 'ICMP': '#059669',
    'DNS': '#d97706', 'ARP': '#dc2626', 'IPv4': '#0891b2',
    'IPv6': '#65a30d', 'ICMPv6': '#9333ea', 'GRE': '#e11d48',
}
_FALLBACK_COLORS = ['#2563eb', '#7c3aed', '#059669', '#d97706', '#dc2626']

_ALLOWED_PER_PAGE = {25, 50, 100, 200}

# ── Packet file-cache helpers ──────────────────────────────────────────────────


def _packets_cache_path(upload: 'PcapFile') -> str:
    return upload.file.name + '.packets.json'


def _write_packet_cache(upload: 'PcapFile', packets: list) -> None:
    path = _packets_cache_path(upload)
    if default_storage.exists(path):
        default_storage.delete(path)
    default_storage.save(path, ContentFile(json.dumps(packets).encode('utf-8')))
    log.debug('pcap.cache.written', pcap_id=upload.pk, path=path, packet_count=len(packets))


def _read_packet_cache(upload: 'PcapFile') -> list | None:
    path = _packets_cache_path(upload)
    if not default_storage.exists(path):
        return None
    with default_storage.open(path) as f:
        return json.loads(f.read())


def _delete_packet_cache(upload: 'PcapFile') -> None:
    path = _packets_cache_path(upload)
    if default_storage.exists(path):
        default_storage.delete(path)
        log.debug('pcap.cache.deleted', pcap_id=upload.pk, path=path)


# ── Access helpers ─────────────────────────────────────────────────────────────


def _has_access(request) -> bool:
    return request.user.is_authenticated or request.session.get('is_guest')


def _get_uploads(request):
    if request.user.is_authenticated:
        return PcapFile.objects.filter(user=request.user).order_by('-uploaded_at')
    return PcapFile.objects.filter(
        session_key=request.session.session_key
    ).order_by('-uploaded_at')


def _get_upload(request, pcap_id) -> PcapFile:
    if request.user.is_authenticated:
        return get_object_or_404(PcapFile, id=pcap_id, user=request.user)
    return get_object_or_404(
        PcapFile, id=pcap_id, session_key=request.session.session_key
    )


# ── Analysis helpers ───────────────────────────────────────────────────────────


def _persist_analysis(upload: PcapFile, packets: list) -> None:
    """Compute summary stats and packet cache from a parsed packet list and save."""
    if not packets:
        log.warning('pcap.persist.empty', pcap_id=upload.pk)
        return

    proto_counts: Counter[str] = Counter(str(p['proto']) for p in packets)
    src_set = {p['src'] for p in packets if p['src'] not in ('-', '')}
    dst_set = {p['dst'] for p in packets if p['dst'] not in ('-', '')}
    total = len(packets)

    upload.total_packets = total
    upload.top_protocol = str(proto_counts.most_common(1)[0][0])
    upload.unique_src_ips = len(src_set)
    upload.unique_dst_ips = len(dst_set)
    upload.capture_duration = float(packets[-1]['time'])
    upload.protocol_bars = [
        {
            'name': proto,
            'count': count,
            'pct': round(count / total * 100),
            'color': _PROTO_COLORS.get(proto, _FALLBACK_COLORS[i % len(_FALLBACK_COLORS)]),
        }
        for i, (proto, count) in enumerate(proto_counts.most_common(5))
    ]
    _write_packet_cache(upload, packets)

    fields = ['total_packets', 'top_protocol', 'unique_src_ips', 'unique_dst_ips',
              'capture_duration', 'protocol_bars']
    if upload.packets_cache is not None:
        upload.packets_cache = None
        fields.append('packets_cache')
    upload.save(update_fields=fields)
    log.info(
        'pcap.stats.saved',
        pcap_id=upload.pk,
        total_packets=total,
        top_protocol=upload.top_protocol,
        unique_src=upload.unique_src_ips,
        unique_dst=upload.unique_dst_ips,
        duration_s=round(upload.capture_duration, 3),
    )


def _get_or_cache_packets(upload: PcapFile) -> tuple[list, str | None]:
    """Return cached packets, migrating old DB cache to file on first access."""
    packets = _read_packet_cache(upload)
    if packets is not None:
        log.debug('pcap.cache_hit', pcap_id=upload.pk, cached_packets=len(packets))
        return packets, None

    # Migrate legacy DB-cached records to file on first access.
    if upload.packets_cache is not None:
        log.info('pcap.cache_migrate', pcap_id=upload.pk,
                 packet_count=len(upload.packets_cache))
        packets = upload.packets_cache
        _write_packet_cache(upload, packets)
        upload.packets_cache = None
        upload.save(update_fields=['packets_cache'])
        return packets, None

    log.info('pcap.cache_miss', pcap_id=upload.pk, filename=upload.file.name)
    try:
        with upload.file.open('rb') as f:
            raw = f.read()
        log.debug('pcap.file_read', pcap_id=upload.pk, size_bytes=len(raw))
        packets = analyze_pcap_bytes(raw)
    except ValueError as exc:
        log.warning('pcap.parse_error', pcap_id=upload.pk, error=str(exc))
        return [], str(exc)

    if packets:
        _persist_analysis(upload, packets)

    return packets, None


def _build_stats(packets: list) -> tuple[dict, str]:
    """Derive display stats and chart JSON from a packet list."""
    proto_counts = Counter(p['proto'] for p in packets)
    src_counts = Counter(p['src'] for p in packets if p['src'] not in ('-', ''))
    dst_counts = Counter(p['dst'] for p in packets if p['dst'] not in ('-', ''))

    top_proto_entry = proto_counts.most_common(1)
    stats = {
        'total': len(packets),
        'top_proto': top_proto_entry[0][0] if top_proto_entry else '-',
        'unique_src': len(src_counts),
        'unique_dst': len(dst_counts),
        'top_src': src_counts.most_common(5),
        'top_dst': dst_counts.most_common(5),
    }
    chart_json = json.dumps({
        'labels': [k for k, _ in proto_counts.most_common(10)],
        'values': [v for _, v in proto_counts.most_common(10)],
    })
    return stats, chart_json


# ── Guest session helpers ──────────────────────────────────────────────────────


def _cleanup_expired_guest_files() -> None:
    """Remove PcapFiles whose guest session no longer exists in the DB."""
    try:
        from django.contrib.sessions.models import Session
        active_keys = set(Session.objects.values_list('session_key', flat=True))
        stale = PcapFile.objects.filter(user=None).exclude(session_key__in=active_keys)
        count = stale.count()
        for f in stale:
            f.file.delete(save=False)
            f.delete()
        if count:
            log.info('guest.cleanup', removed=count)
    except Exception:
        log.exception('guest.cleanup_failed')


# ── Guest views ────────────────────────────────────────────────────────────────


def guest_login(request):
    try:
        from main.actors import CleanupActor
        CleanupActor.start().tell({})
    except Exception:
        log.exception('actor.cleanup_failed')
        _cleanup_expired_guest_files()
    request.session.flush()
    request.session['is_guest'] = True
    log.info('guest.login', session_key=request.session.session_key)
    return redirect('homepage')


def guest_logout(request):
    deleted = 0
    if request.session.get('is_guest') and request.session.session_key:
        for upload in PcapFile.objects.filter(session_key=request.session.session_key):
            _delete_packet_cache(upload)
            upload.file.delete(save=False)
            upload.delete()
            deleted += 1
    log.info('guest.logout', session_key=request.session.session_key, files_deleted=deleted)
    request.session.flush()
    return redirect('login')


# ── Main views ─────────────────────────────────────────────────────────────────


def homepage(request):
    if not _has_access(request):
        return redirect('login')

    if request.user.is_authenticated:
        request.session.pop('is_guest', None)

    uploads = _get_uploads(request)
    log.debug(
        'homepage.view',
        user=request.user.username if request.user.is_authenticated else 'guest',
        upload_count=uploads.count(),
    )

    if request.method == 'POST':
        form = PcapUploadForm(request.POST, request.FILES)
        if form.is_valid():
            upload = form.save(commit=False)
            if request.user.is_authenticated:
                upload.user = request.user
            else:
                upload.session_key = request.session.session_key
            upload.save()
            log.info('pcap.uploaded', pcap_id=upload.pk, filename=upload.file.name)

            # Kick off background analysis; fall back gracefully if Pykka unavailable
            try:
                from main.actors import PcapAnalyzerActor
                PcapAnalyzerActor.start().tell({'pcap_id': upload.pk})
            except Exception:
                log.exception('actor.start_failed', pcap_id=upload.pk)
                _persist_analysis_safe(upload)

            messages.success(request, 'PCAP uploaded successfully.')
            return redirect('homepage')
        else:
            messages.error(request, 'Upload failed. Please try again.')
    else:
        form = PcapUploadForm()

    return render(
        request,
        'homepage.html',
        {
            'form': form,
            'uploads': uploads,
            'is_guest': not request.user.is_authenticated and request.session.get('is_guest', False),
        },
    )


def _persist_analysis_safe(upload: PcapFile) -> None:
    """Synchronous fallback: parse and persist without raising."""
    try:
        with upload.file.open('rb') as f:
            packets = analyze_pcap_bytes(f.read())
        _persist_analysis(upload, packets)
    except Exception:
        log.exception('pcap.sync_analyze_failed', pcap_id=upload.pk)


def register(request):
    form = UserRegistrationForm()

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            log.info('user.register.attempt', username=user.username, email=form.cleaned_data['email'])

            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string(
                'main/email_activation/activate_email_message.html',
                {
                    'user': form.cleaned_data['username'],
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                },
            )
            to_email = form.cleaned_data['email']
            try:
                from main.actors import EmailActor
                EmailActor.start().tell({'subject': mail_subject, 'body': message, 'to': [to_email]})
            except Exception:
                log.exception('actor.email_failed', to=to_email)
                EmailMessage(mail_subject, message, to=[to_email]).send()
            log.info('user.register.success', username=user.username, email=to_email)
            messages.success(
                request,
                'Account created successfully. Please check your email to activate your account.',
            )
            return redirect('login')
        else:
            log.warning('user.register.failed', errors=form.errors.as_json())
            messages.error(request, 'Account creation failed. Please try again.')

    return render(request, 'main/register.html', {'form': form})


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        log.warning('user.activate.invalid_link', uidb64=uidb64)
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        log.info('user.activate.success', user_id=user.pk, username=user.username)
        return render(request, 'main/email_activation/activation_successful.html')
    log.warning('user.activate.failed', uidb64=uidb64, user_id=user.pk if user else None)
    return render(request, 'main/email_activation/activation_unsuccessful.html')


def delete_pcap(request, pcap_id):
    if not _has_access(request):
        return redirect('login')

    upload = _get_upload(request, pcap_id)
    if request.method == 'POST':
        log.info('pcap.deleted', pcap_id=upload.pk)
        _delete_packet_cache(upload)
        upload.file.delete(save=False)
        upload.delete()
        messages.success(request, 'Upload deleted.')
    return redirect('homepage')


def analysis(request, pcap_id):
    if not _has_access(request):
        return redirect('login')

    upload = _get_upload(request, pcap_id)
    log.debug(
        'analysis.view',
        pcap_id=pcap_id,
        user=request.user.username if request.user.is_authenticated else 'guest',
    )
    all_packets, error = _get_or_cache_packets(upload)

    stats: dict = {}
    chart_json = '{}'
    proto_list: list[str] = []

    if all_packets and not error:
        stats, chart_json = _build_stats(all_packets)
        proto_list = sorted({str(p['proto']) for p in all_packets})

    # Apply search / protocol filter
    q            = request.GET.get('q', '').strip()
    proto_filter = request.GET.get('proto', '').strip()
    packets      = all_packets

    if q:
        q_lower = q.lower()
        packets = [
            p for p in packets
            if q_lower in str(p.get('src', '')).lower()
            or q_lower in str(p.get('dst', '')).lower()
            or q_lower in str(p.get('proto', '')).lower()
            or q_lower in str(p.get('info', '')).lower()
        ]
        log.debug('analysis.filter.text', pcap_id=pcap_id, q=q,
                  matched=len(packets), total=len(all_packets))

    if proto_filter:
        packets = [p for p in packets if str(p.get('proto')) == proto_filter]
        log.debug('analysis.filter.proto', pcap_id=pcap_id, proto=proto_filter,
                  matched=len(packets))

    # Build a stable query-string fragment so filter survives pagination
    _filter_parts = {}
    if q:
        _filter_parts['q'] = q
    if proto_filter:
        _filter_parts['proto'] = proto_filter
    filter_qs = ('&' + urlencode(_filter_parts)) if _filter_parts else ''

    try:
        per_page = int(request.GET.get('per_page', 25))
        if per_page not in _ALLOWED_PER_PAGE:
            log.debug('analysis.invalid_per_page', requested=per_page, fallback=25)
            per_page = 25
    except (ValueError, TypeError):
        per_page = 25

    paginator = Paginator(packets, per_page)
    page_obj  = paginator.get_page(request.GET.get('page'))

    current     = page_obj.number
    total_pages = paginator.num_pages
    page_window = list(range(max(1, current - 4), min(total_pages + 1, current + 5)))

    return render(
        request,
        'analysis.html',
        {
            'upload': upload,
            'page_obj': page_obj,
            'per_page': per_page,
            'page_window': page_window,
            'error': error,
            'stats': stats,
            'chart_json': chart_json,
            'is_guest': not request.user.is_authenticated and request.session.get('is_guest', False),
            'q': q,
            'proto_filter': proto_filter,
            'proto_list': proto_list,
            'total_packets': len(all_packets),
            'filtered_count': len(packets),
            'filter_qs': filter_qs,
        },
    )
