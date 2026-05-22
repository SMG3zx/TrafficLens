from django.conf import settings
from django.db import models


class PcapFile(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='pcap_files',
        null=True,
        blank=True,
    )
    session_key = models.CharField(max_length=40, null=True, blank=True, db_index=True)
    file = models.FileField(upload_to='pcaps/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Pre-computed at upload time so the dashboard doesn't re-parse every PCAP
    total_packets = models.PositiveIntegerField(null=True, blank=True)
    top_protocol = models.CharField(max_length=50, null=True, blank=True)
    unique_src_ips = models.PositiveIntegerField(null=True, blank=True)
    unique_dst_ips = models.PositiveIntegerField(null=True, blank=True)
    capture_duration = models.FloatField(null=True, blank=True)
    # List of {name, count, pct, color} dicts for the top-5 protocol bars
    protocol_bars = models.JSONField(null=True, blank=True)

    def __str__(self) -> str:
        owner = self.user.username if self.user_id else f"guest:{self.session_key}"
        return f"{owner} - {self.file.name}"

    @property
    def size_display(self) -> str:
        try:
            size = self.file.size
        except Exception:
            return '—'
        if size < 1024:
            return f'{size} B'
        if size < 1024 * 1024:
            return f'{size / 1024:.1f} KB'
        return f'{size / (1024 * 1024):.1f} MB'

    @property
    def duration_display(self) -> str:
        if self.capture_duration is None:
            return '—'
        if self.capture_duration < 60:
            return f'{self.capture_duration:.2f}s'
        return f'{self.capture_duration / 60:.1f}min'