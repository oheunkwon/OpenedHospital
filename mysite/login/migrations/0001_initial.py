# Generated by Django 3.1.1 on 2020-09-06 02:39

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Users',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('uid', models.CharField(blank=True, max_length=255, null=True)),
                ('email', models.CharField(blank=True, max_length=255, null=True)),
                ('pwd', models.CharField(blank=True, max_length=255, null=True)),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('address', models.CharField(blank=True, max_length=255, null=True)),
                ('x', models.FloatField(blank=True, null=True)),
                ('y', models.FloatField(blank=True, null=True)),
                ('createdat', models.DateTimeField(blank=True, db_column='createdAt', null=True)),
                ('updatedat', models.DateTimeField(blank=True, db_column='updatedAt', null=True)),
            ],
            options={
                'db_table': 'Users',
                'managed': False,
            },
        ),
    ]
