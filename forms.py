from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, Email

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    sector = StringField('Sector', validators=[DataRequired()])
    submit = SubmitField('Register')

class OSForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    rh = BooleanField('RH')
    semst = BooleanField('SEMST')
    comercial = BooleanField('COMERCIAL')
    financeiro = BooleanField('FINANCEIRO')
    suprimentos = BooleanField('SUPRIMENTOS')
    operacional = BooleanField('OPERACIONAL')
    dp = BooleanField('DP')
    recepcao = BooleanField('RECEPÇÃO')
    ti = BooleanField('TI')
    submit = SubmitField('Create OS')

class EditOSForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired()])
    file = FileField('Arquivo')
    submit = SubmitField('Salvar')
