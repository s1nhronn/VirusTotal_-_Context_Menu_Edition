import time
import winreg
import sys
import traceback
from contextlib import suppress
from pprint import pprint

import vt
import colorama
import threading
import hashlib


# noinspection SpellCheckingInspection
class bcolors:
    """
    Класс для цветного текста в выводе через print()
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


stop = False


def load_animation():
    while not stop:
        if stop:
            break
        print('\rСканируем полученный файл.  ', end='', flush=True)
        time.sleep(0.5)
        if stop:
            break
        print('\rСканируем полученный файл.. ', end='', flush=True)
        time.sleep(0.5)
        if stop:
            break
        print('\rСканируем полученный файл...', end='', flush=True)
        if stop:
            break
        time.sleep(0.5)


if __name__ == '__main__':
    # noinspection PyBroadException
    try:
        colorama.init()
        # Получение файла из списка аргументов
        path = sys.argv[1]
        print(bcolors.HEADER + 'Файл: ' + path + bcolors.ENDC)
        hash_ = hashlib.md5(open(path, 'rb').read()).hexdigest()

        # Получение API ключа и создание клиента
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '*\\shell\\VirusTotal')
        except FileNotFoundError:
            import platform

            bitness = platform.architecture()[0]
            other_view_flag = None
            if bitness == '32bit':
                other_view_flag = winreg.KEY_WOW64_64KEY
            elif bitness == '64bit':
                other_view_flag = winreg.KEY_WOW64_32KEY

            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '*\\shell\\VirusTotal',
                                 access=winreg.KEY_READ | other_view_flag)
        api_key = winreg.QueryValueEx(key, 'APIKEY')[0]
        key.Close()

        # Сканирование файла и вывод ответа
        print(bcolors.BOLD, end='')
        p = threading.Thread(target=load_animation)
        p.start()
        client = vt.Client(api_key)
        with suppress(vt.error.APIError):
            file_info = client.get_object('/files/' + hash_)
            antivirus_results = file_info.to_dict()['attributes']['last_analysis_results']
            stop = True
            print(bcolors.BOLD + '\rПроверяем результаты...     ' + bcolors.ENDC)
            dct = {}
            for i in antivirus_results:
                if antivirus_results[i]['result'] is not None:
                    dct[i] = antivirus_results[i]
            if dct:
                print(bcolors.FAIL + 'В файле обнаружены вирусы!\n' + bcolors.ENDC)
                print(bcolors.UNDERLINE + 'Антивирус: Тип угрозы' + bcolors.ENDC)
                for i in dct:
                    print(bcolors.OKGREEN + i + bcolors.ENDC + ': ' + bcolors.FAIL + dct[i]['result'] + bcolors.ENDC)
            else:
                print(bcolors.OKGREEN + 'В файле не обнаружены вирусы!' + bcolors.ENDC)

            client.close()
            print()
            input('Press Enter to exit...')
            sys.exit()
        with open(path, 'rb') as file:
            res = client.scan_file(file, wait_for_completion=True).to_dict()
        antivirus_results = res['attributes']['results']
        stop = True
        print(bcolors.BOLD + '\rПроверяем результаты...     ' + bcolors.ENDC)
        dct = {}
        for i in antivirus_results:
            if antivirus_results[i]['result'] is not None:
                dct[i] = antivirus_results[i]
        if dct:
            print(bcolors.FAIL + 'В файле обнаружены вирусы или трояны!\n' + bcolors.ENDC)
            print(bcolors.UNDERLINE + 'Антивирус: Тип угрозы' + bcolors.ENDC)
            for i in dct:
                print(bcolors.OKGREEN + i + bcolors.ENDC + ': ' + bcolors.FAIL + dct[i]['result'] + bcolors.ENDC)
        else:
            print(bcolors.OKGREEN + 'В файле не обнаружены вирусы!' + bcolors.ENDC)

        client.close()
    except Exception:
        print(bcolors.FAIL + 'Произошла ошибка!')
        print(traceback.format_exc() + bcolors.ENDC)
    print()
    input('Press Enter to exit...')
