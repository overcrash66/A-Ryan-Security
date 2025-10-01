from marshmallow import Schema, fields, validate

class LoginSchema(Schema):
    """Schema for validating login data."""
    username = fields.Str(required=True, validate=validate.Length(min=3, max=64))
    password = fields.Str(required=True, validate=validate.Length(min=8))

class UserSchema(Schema):
    """Schema for user data validation."""
    username = fields.Str(required=True, validate=validate.Length(min=3, max=64))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    role = fields.Str(validate=validate.OneOf(['user', 'admin']))

class IssueSchema(Schema):
    """Schema for issue data validation."""
    category = fields.Str(required=True)
    description = fields.Str(required=True)
    severity = fields.Str(required=True, validate=validate.OneOf(['Low', 'Medium', 'High', 'Critical']))
    status = fields.Str(validate=validate.OneOf(['open', 'in_progress', 'resolved', 'closed']))
    assigned_to = fields.Int(allow_none=True)

class ConfigSchema(Schema):
    """Schema for configuration validation."""
    scan_interval = fields.Int(validate=validate.Range(min=1, max=24))
    alert_threshold = fields.Str(validate=validate.OneOf(['Low', 'Medium', 'High']))
    email_notifications = fields.Bool()
    backup_enabled = fields.Bool()
    backup_frequency = fields.Int(validate=validate.Range(min=1, max=30))
