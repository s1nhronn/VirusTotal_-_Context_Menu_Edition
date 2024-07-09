import winreg
import os

from contextlib import suppress


def add_to_registry(api_key: str):
    key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r'*\shell\VirusTotal')

    winreg.SetValueEx(key, 'MUIVerb', None, winreg.REG_SZ, "Проверить на вирусы")
    winreg.SetValueEx(key, 'Icon', None, winreg.REG_SZ, os.getcwd() + r'\VirusTotal.ico')
    winreg.SetValueEx(key, 'APIKEY', None, winreg.REG_SZ, api_key)

    path_to_script = os.path.abspath('main.exe')

    winreg.SetValue(key, 'command', winreg.REG_SZ, path_to_script + ' "%1"')

    key.Close()


def remove_from_registry():
    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r'*\shell\VirusTotal\command')
    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r'*\shell\VirusTotal')


if __name__ == '__main__':
    res = input('1 - Добавить команду в контекстное меню\n2 - Удалить команду из контекстного меню\n[1/2]:')
    if res == '1':
        api_key = input('Введите ваш API-ключ: ')
        add_to_registry(api_key)
        print('Done')
        input('Press Enter to exit...')
    else:
        with suppress(FileNotFoundError):
            remove_from_registry()
        print('Done')
        input('Press Enter to exit...')
