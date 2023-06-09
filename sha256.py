import hashlib

def hash_password(password):
    # Şifreyi karma algoritmasıyla hashleme
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def check_password(password, hashed_password):
    # Girilen şifrenin hashlenmiş haliyle kaydedilen hashin eşleşip eşleşmediğini kontrol etme
    if hashlib.sha256(password.encode()).hexdigest() == hashed_password:
        return True
    else:
        return False

# Kullanıcıdan şifre alıp hashleme
password = input("Şifrenizi girin: ")
hashed_password = hash_password(password)
print("Hashlenmiş şifre:", hashed_password)

# Şifre kontrolü
check_password_input = input("Kontrol etmek istediğiniz şifreyi girin: ")
if check_password(check_password_input, hashed_password):
    print("Şifre doğru.")
else:
    print("Şifre yanlış.")
