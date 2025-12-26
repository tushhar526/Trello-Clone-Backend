from rest_framework import serializers
from .models import UserModel


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ["user_id", "username", "password"]

    def validate(self, data):
        if "password" not in data:
            raise serializers.ValidationError({"password": "password is required"})

        if not data["password"].strip():
            raise serializers.ValidationError({"password": "Password cannot be empty"})

        if len(data["password"]) < 8:
            raise serializers.ValidationError(
                {"password": "Password can not be less then 8 characters"}
            )

        return data

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        user = UserModel.objects.create(**validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user
