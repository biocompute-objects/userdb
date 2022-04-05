# Generated by Django 3.1.7 on 2022-03-17 16:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Prefixes',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=100)),
                ('prefix', models.CharField(max_length=5)),
                ('registration_date', models.DateTimeField()),
                ('registration_certificate', models.CharField(max_length=1000)),
            ],
        ),
    ]
