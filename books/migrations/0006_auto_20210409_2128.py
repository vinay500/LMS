# Generated by Django 3.1.2 on 2021-04-09 15:58

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('books', '0005_auto_20210408_1900'),
    ]

    operations = [
        migrations.AlterField(
            model_name='books',
            name='userid',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='books',
            name='username',
            field=models.CharField(max_length=30, null=True),
        ),
    ]
