from django.contrib import admin
from .models import PcapFile


@admin.register(PcapFile)
class PcapFileAdmin(admin.ModelAdmin):
    list_display = ('user', 'file', 'uploaded_at')
    list_filter = ('user',)
    ordering = ('-uploaded_at',)
    readonly_fields = ('uploaded_at',)
