import django_filters
from .models import *
class ComplaintFilter(django_filters.FilterSet):
    class Meta:
        model = ComplaintModel
        fields = '__all__'
        filter_overrides = {
            models.FileField: {
                'filter_class': django_filters.CharFilter,
                'extra': lambda f: {
                    'lookup_expr': 'icontains', 
                },
            },
        }
class UserInfoFilter(django_filters.FilterSet):
    class Meta:
        model = UserInfoModel
        fields = '__all__'
class CommentFilter(django_filters.FilterSet):
    class Meta:
        model = CommentModel
        fields = '__all__'