import json
from collections import Counter

from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from main.forms import UserRegistrationForm, PcapUploadForm
from trafficlens_core import analyze_pcap_bytes
from .models import PcapFile

# ── Access helpers ─────────────────────────────────────────────────────────────


def _has_access(request):
    return request.user.is_authenticated or request.session.get("is_guest")


def _get_uploads(request):
    if request.user.is_authenticated:
        return PcapFile.objects.filter(user=request.user).order_by("-uploaded_at")
    return PcapFile.objects.filter(session_key=request.session.session_key).order_by(
        "-uploaded_at"
    )


def _get_upload(request, pcap_id):
    if request.user.is_authenticated:
        return get_object_or_404(PcapFile, id=pcap_id, user=request.user)
    return get_object_or_404(
        PcapFile, id=pcap_id, session_key=request.session.session_key
    )


_PROTO_COLORS = {
    'TCP': '#2563eb', 'UDP': '#7c3aed', 'ICMP': '#059669',
    'DNS': '#d97706', 'ARP': '#dc2626', 'IPv4': '#0891b2',
    'IPv6': '#65a30d', 'ICMPv6': '#9333ea', 'GRE': '#e11d48',
}
_FALLBACK_COLORS = ['#2563eb', '#7c3aed', '#059669', '#d97706', '#dc2626']


def _compute_pcap_stats(upload: PcapFile) -> None:
    """Parse the uploaded PCAP and persist summary stats on the row."""
    try:
        with upload.file.open("rb") as f:
            packets = analyze_pcap_bytes(f.read())
    except Exception:
        return
    if not packets:
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
    upload.protocol_bars = [  # type: ignore[assignment]
        {
            'name': proto,
            'count': count,
            'pct': round(count / total * 100),
            'color': _PROTO_COLORS.get(proto, _FALLBACK_COLORS[i % len(_FALLBACK_COLORS)]),
        }
        for i, (proto, count) in enumerate(proto_counts.most_common(5))
    ]
    upload.save(update_fields=[
        'total_packets', 'top_protocol', 'unique_src_ips',
        'unique_dst_ips', 'capture_duration', 'protocol_bars',
    ])


def _cleanup_expired_guest_files():
    """Remove PcapFiles whose guest session no longer exists in the DB."""
    try:
        from django.contrib.sessions.models import Session

        active_keys = set(Session.objects.values_list("session_key", flat=True))
        stale = PcapFile.objects.filter(user=None).exclude(session_key__in=active_keys)
        for f in stale:
            f.file.delete(save=False)
            f.delete()
    except Exception:
        pass


# ── Guest views ────────────────────────────────────────────────────────────────


def guest_login(request):
    _cleanup_expired_guest_files()
    request.session.flush()
    request.session["is_guest"] = True
    return redirect("homepage")


def guest_logout(request):
    if request.session.get("is_guest") and request.session.session_key:
        for upload in PcapFile.objects.filter(session_key=request.session.session_key):
            upload.file.delete(save=False)
            upload.delete()
    request.session.flush()
    return redirect("login")


# ── Main views ─────────────────────────────────────────────────────────────────


def homepage(request):
    if not _has_access(request):
        return redirect("login")

    uploads = _get_uploads(request)

    if request.method == "POST":
        form = PcapUploadForm(request.POST, request.FILES)
        if form.is_valid():
            upload = form.save(commit=False)
            if request.user.is_authenticated:
                upload.user = request.user
            else:
                upload.session_key = request.session.session_key
            upload.save()
            _compute_pcap_stats(upload)
            messages.success(request, "PCAP uploaded successfully.")
            return redirect("homepage")
        else:
            messages.error(request, "Upload failed. Please try again.")
    else:
        form = PcapUploadForm()

    return render(
        request,
        "homepage.html",
        {
            "form": form,
            "uploads": uploads,
            "is_guest": request.session.get("is_guest", False),
        },
    )


def register(request):
    form = UserRegistrationForm()

    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            current_site = get_current_site(request)
            mail_subject = "Activate your account."
            message = render_to_string(
                "main/email_activation/activate_email_message.html",
                {
                    "user": form.cleaned_data["username"],
                    "domain": current_site.domain,
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": default_token_generator.make_token(user),
                },
            )
            to_email = form.cleaned_data["email"]
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()
            messages.success(
                request,
                "Account created successfully. Please check your email to activate your account.",
            )
            return redirect("login")
        else:
            messages.error(request, "Account creation failed. Please try again.")

    return render(request, "main/register.html", {"form": form})


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, "main/email_activation/activation_successful.html")
    else:
        return render(request, "main/email_activation/activation_unsuccessful.html")


def delete_pcap(request, pcap_id):
    if not _has_access(request):
        return redirect("login")

    upload = _get_upload(request, pcap_id)
    if request.method == "POST":
        upload.file.delete(save=False)
        upload.delete()
        messages.success(request, "Upload deleted.")
    return redirect("homepage")


def analysis(request, pcap_id):
    if not _has_access(request):
        return redirect("login")

    upload = _get_upload(request, pcap_id)

    packets_rows = []
    error = None
    stats = {}
    chart_json = "{}"

    try:
        with upload.file.open("rb") as pcap_file:
            packets_rows = analyze_pcap_bytes(pcap_file.read())
    except ValueError as exc:
        error = str(exc)

    if packets_rows and not error:
        proto_counts = Counter(p["proto"] for p in packets_rows)
        src_counts = Counter(
            p["src"] for p in packets_rows if p["src"] not in ("-", "")
        )
        dst_counts = Counter(
            p["dst"] for p in packets_rows if p["dst"] not in ("-", "")
        )

        top_proto_entry = proto_counts.most_common(1)
        stats = {
            "total": len(packets_rows),
            "top_proto": top_proto_entry[0][0] if top_proto_entry else "-",
            "unique_src": len(src_counts),
            "unique_dst": len(dst_counts),
            "top_src": src_counts.most_common(5),
            "top_dst": dst_counts.most_common(5),
        }
        chart_json = json.dumps(
            {
                "labels": [k for k, _ in proto_counts.most_common(10)],
                "values": [v for _, v in proto_counts.most_common(10)],
            }
        )

    paginator = Paginator(packets_rows, 200)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "analysis.html",
        {
            "upload": upload,
            "page_obj": page_obj,
            "error": error,
            "stats": stats,
            "chart_json": chart_json,
            "is_guest": request.session.get("is_guest", False),
        },
    )
