from django.http import JsonResponse, HttpResponse
from django.template.response import TemplateResponse
from django.utils.deprecation import MiddlewareMixin

class CustomMiddleware(MiddlewareMixin):
    def __init__(self, get_response=None):
        self.get_response = get_response
        print("CustomMiddleware initialized")

    def __call__(self, request):
        print("CustomMiddleware __call__: Request received")
        response = self.get_response(request)
        print("CustomMiddleware __call__: Response generated")
        return response

    def process_request(self, request):
        print(f"Processing request: {request.path}")
        if not request.user.is_authenticated:
            print("User not authenticated, returning JsonResponse")
            return JsonResponse({'error': 'Authentication required.'}, status=401)
        print("User authenticated")

    def process_view(self, request, view_func, view_args, view_kwargs):
        print(f"Processing view: {view_func.__name__}")
        
    # def process_template_response(self, request, response):
    #     print("CustomMiddleware process_template_response")
    #     if isinstance(response, TemplateResponse):
    #         print("Response is a TemplateResponse")
    #         response.context_data['custom_data'] = 'value'
    #     return response

    def process_response(self, request, response):
        print("process_response fn: Processing response")
        response['X-Custom-Header'] = 'Custom Value'
        return response

    def process_exception(self, request, exception):
        print(f"Exception occurred: {exception}")
        return JsonResponse({'error': 'An internal error occurred. Please try again later.'}, status=500)     
        