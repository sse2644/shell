from django_elasticsearch_dsl import Document, Index, fields
from django_elasticsearch_dsl.registries import registry
from .models import WebShellcode, LinuxShellcode, WindowsShellcode

web_index = Index('web_index')
linux_index = Index('linux_index')
windows_index = Index('windows_index')

@registry.register_document
class WebShellcodeDocument(Document):
    title = fields.TextField(
        analyzer='standard',
        fields={'raw': fields.KeywordField()}
    )
    content = fields.TextField(analyzer='standard')
    file_type = fields.KeywordField()
    uploaded_at = fields.DateField()

    class Index:
        name = 'web_index'
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }

    class Django:
        model = WebShellcode
        fields = ['id']

@registry.register_document
class LinuxShellcodeDocument(Document):
    title = fields.TextField(
        analyzer='standard',
        fields={'raw': fields.KeywordField()}
    )
    content = fields.TextField(analyzer='standard')
    file_type = fields.KeywordField()
    uploaded_at = fields.DateField()

    class Index:
        name = 'linux_index'
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }

    class Django:
        model = LinuxShellcode
        fields = ['id']

@registry.register_document
class WindowsShellcodeDocument(Document):
    title = fields.TextField(
        analyzer='standard',
        fields={'raw': fields.KeywordField()}
    )
    content = fields.TextField(analyzer='standard')
    file_type = fields.KeywordField()
    uploaded_at = fields.DateField()

    class Index:
        name = 'windows_index'
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }

    class Django:
        model = WindowsShellcode
        fields = ['id']