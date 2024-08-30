from django.core.management.base import BaseCommand
from spy.models import WebShellcode, LinuxShellcode, WindowsShellcode
from spy.documents import WebShellcodeDocument, LinuxShellcodeDocument, WindowsShellcodeDocument

class Command(BaseCommand):
    help = 'Synchronize MySQL data to Elasticsearch'

    def handle(self, *args, **options):
        self.sync_web_shellcodes()
        self.sync_linux_shellcodes()
        self.sync_windows_shellcodes()
        self.stdout.write(self.style.SUCCESS('Successfully synchronized data'))

    def sync_web_shellcodes(self):
        WebShellcodeDocument.init()
        for shellcode in WebShellcode.objects.all():
            WebShellcodeDocument.update(shellcode)

    def sync_linux_shellcodes(self):
        LinuxShellcodeDocument.init()
        for shellcode in LinuxShellcode.objects.all():
            LinuxShellcodeDocument.update(shellcode)

    def sync_windows_shellcodes(self):
        WindowsShellcodeDocument.init()
        for shellcode in WindowsShellcode.objects.all():
            WindowsShellcodeDocument.update(shellcode)