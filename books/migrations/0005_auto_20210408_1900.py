# Generated by Django 3.1.2 on 2021-04-08 13:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('books', '0004_auto_20201220_2301'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='books',
            name='book_author',
        ),
        migrations.AddField(
            model_name='books',
            name='userid',
            field=models.IntegerField(null=True),
        ),
    ]
