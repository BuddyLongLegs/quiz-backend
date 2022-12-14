# Generated by Django 4.1.2 on 2022-10-11 22:25

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('name', models.CharField(max_length=64)),
                ('username', models.CharField(max_length=32, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('score', models.IntegerField(default=0)),
                ('hash', models.CharField(max_length=300)),
            ],
        ),
    ]
