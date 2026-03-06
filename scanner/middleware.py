import secrets

DEVICE_COOKIE_NAME = "malscan_device"
DEVICE_COOKIE_AGE = 60 * 60 * 24 * 365 * 2


class DeviceIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        device_id = request.COOKIES.get(DEVICE_COOKIE_NAME)
        if not device_id:
            device_id = secrets.token_urlsafe(24)
            request._set_device_cookie = device_id
        request.device_id = device_id

        response = self.get_response(request)

        # set cookie if needed
        if hasattr(request, "_set_device_cookie"):
            response.set_cookie(
                DEVICE_COOKIE_NAME,
                request._set_device_cookie,
                max_age=DEVICE_COOKIE_AGE,
                httponly=True,
                samesite="Lax",
                secure=False,  # True если HTTPS
            )
        return response
