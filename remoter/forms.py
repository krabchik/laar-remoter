from flask_wtf import FlaskForm
from wtforms import StringField, SelectMultipleField, FieldList, FormField, BooleanField, HiddenField, PasswordField, \
                     SelectField, IntegerField
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, IPAddress, NumberRange, ValidationError, Optional


class IPForm(FlaskForm):
    ip = StringField(validators=[DataRequired(), IPAddress(message='Invalid IP')])


class IPCheckboxForm(FlaskForm):
    ip_selected = BooleanField('Select')


class RunForm(FlaskForm):
    ip_addresses = SelectMultipleField('IP Addresses', choices=[], validators=[DataRequired(), IPAddress(message='Invalid IP')])
    # reboot = SubmitField('Reboot')
    # ip_addresses = FieldList(BooleanField(), min_entries=10)


class DeviceForm(FlaskForm):
    device_id = HiddenField('ID', validators=[DataRequired()])
    ip = HiddenField('IP Address', validators=[DataRequired(), IPAddress(message='Invalid IP')])
    os_type = HiddenField('OS', validators=[DataRequired()])

    device_name = StringField('Device name')
    username = StringField('OS Username', validators=[DataRequired()])
    password = StringField('OS Password')
    connect_type = SelectField('Connect Type', choices=[('ssh', 'SSH'), ('paexec', 'PAExec')])
    ssh_port = IntegerField('SSH Port', validators=[Optional(), NumberRange(min=1, max=65535)])
    ssh_use_key = BooleanField('Use ssh key')
    ssh_key = FileField('SSH Key')

    def validate_connect_type(self, field):
        if self.os_type.data != 'Windows' and field.data == 'paexec':
            raise ValidationError('Invalid connect type')

    def validate_password(self, field):
        if field.data and not self.username:
            raise ValidationError('For password authentication username name must be provided')

    def validate_device_id(self, field):
        try:
            if int(field.data) < 0:
                raise ValidationError('Invalid device ID')
        except ValueError:
            raise ValidationError('Invalid device ID')

    def validate(self, *args, **kwargs):
        if not super().validate(*args, **kwargs):
            return False

        if self.connect_type.data == 'ssh':
            if not (self.username.data and self.password.data) and not self.ssh_key.data:
                if not self.username.data:
                    self.username.errors.append('Either username and password or SSH key is required.')
                if not self.password.data:
                    self.password.errors.append('Either username and password or SSH key is required.')
                if not self.ssh_key.data:
                    self.ssh_key.errors.append('Either username and password or SSH key is required.')
                return False

        return True


class DeviceFormSet(FlaskForm):
    devices = FieldList(FormField(DeviceForm))
