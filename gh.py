# Открытие файла с кодировкой UTF-8 (или другой, если необходимо)
with open('passwordProtector.pyc', 'r', encoding='utf-8') as file:
    содержимое = file.read()

print(содержимое)

