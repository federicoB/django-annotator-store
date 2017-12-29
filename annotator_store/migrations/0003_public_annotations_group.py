from django.contrib.auth.models import Group
from django.db import migrations
#import settings to read ANNOTATION_OBJECT_PERMISSIONS flag
from django.conf import settings

def create_public_annotations_group(apps, schema_editor):
    ANNOTATION_OBJECT_PERMISSIONS = getattr(settings, 'ANNOTATION_OBJECT_PERMISSIONS',
                                            False)
    if ANNOTATION_OBJECT_PERMISSIONS:
        Group.objects.create(name="public_permissions")

def remove_public_annotations_group(apps, schema_editor):
    """for backward migrations"""
    ANNOTATION_OBJECT_PERMISSIONS = getattr(settings, 'ANNOTATION_OBJECT_PERMISSIONS',
                                            False)
    if ANNOTATION_OBJECT_PERMISSIONS:
        Group.objects.filter(name="public_permissions").delete()


class Migration(migrations.Migration):

    dependencies = [
        ('annotator_store', '0002_annotation_quote_text_optional'),
    ]

    operations = [
        migrations.RunPython(create_public_annotations_group,remove_public_annotations_group),
    ]