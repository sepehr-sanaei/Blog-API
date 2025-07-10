"""
Django custom command for waiting for database to be ready.
"""
import time

from django.core.management.base import BaseCommand
from django.db.utils import OperationalError

from psycopg import OperationalError as Psycopg2OpError


class Command(BaseCommand):
    """Django command for waiting for db."""

    def handle(self, *args, **options):
        """Entrypoint for the command."""
        self.stdout.write('Waiting for database...')
        db_up = False

        while db_up is False:
            try:
                self.check(databases=['default'])
                db_up = True
            except (Psycopg2OpError, OperationalError):
                self.stdout.write('Database unavailable, waiting 1 second.')
                time.sleep(1)
        self.stdout.write(self.style.SUCCESS('Database is available.'))
