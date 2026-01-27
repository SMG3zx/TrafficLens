from django.db import models
from django.contrib.auth.models import User


class PcapFile(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='pcap_files'
    )
    file = models.FileField(upload_to='pcaps/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.file.name}"