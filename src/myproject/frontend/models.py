from django.db import models

# Create your models here.
# models.py (en la aplicación correcta, como 'chat/models.py')
from django.contrib.auth.models import User

class Chat(models.Model):
    user1 = models.ForeignKey(User, related_name="chats_user1", on_delete=models.CASCADE)
    user2 = models.ForeignKey(User, related_name="chats_user2", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Chat between {self.user1.username} and {self.user2.username}"
