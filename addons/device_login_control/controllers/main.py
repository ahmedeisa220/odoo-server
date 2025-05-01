from odoo import http
from odoo.http import request

class AuthController(http.Controller):

    @http.route('/custom_login', type='json', auth='none', csrf=False)
    def custom_login(self, **kwargs):
        login = kwargs.get('login')
        password = kwargs.get('password')
        device_id = kwargs.get('device_id')

        user = request.env['res.users'].sudo().search([('login', '=', login)], limit=1)
        if not user:
            return {'error': 'Invalid login'}

        if not user._check_password(password):
            return {'error': 'Wrong password'}

        if user.x_device_id:
            if user.x_device_id != device_id:
                return {'error': 'This device is not authorized for this account'}
        else:
            user.sudo().write({'x_device_id': device_id})

        request.session.authenticate(request.env.cr.dbname, login, password)
        return {'success': True, 'uid': user.id}
