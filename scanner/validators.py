from django.core.exceptions import ValidationError


def validate_file_size(value):
    # Set your size limit here (e.g., 100 MB)
    limit = 100 * 1024 * 1024
    if value.size > limit:
        raise ValidationError('File too large. Size should not exceed 5 MiB.')
