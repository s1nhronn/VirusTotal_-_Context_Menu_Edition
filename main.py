import time
import winreg
import sys
import traceback
import vt
import colorama
import multiprocessing


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


def loading_animation():
    print(bcolors.BOLD, end='', flush=True)
    while True:
        print('\rСканируем полученный файл.  ', end='', flush=True)
        time.sleep(0.5)
        print('\rСканируем полученный файл.. ', end='', flush=True)
        time.sleep(0.5)
        print('\rСканируем полученный файл...', end='', flush=True)
        time.sleep(0.5)


if __name__ == '__main__':
    # noinspection PyBroadException
    try:
        colorama.init()
        # Получение файла из списка аргументов
        path = sys.argv[1]
        print(bcolors.HEADER + 'Файл: ' + path + bcolors.ENDC)

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

        client = vt.Client(api_key)

        # Сканирование файла и вывод ответа
        p = multiprocessing.Process(target=loading_animation)
        p.start()
        with open(path, 'rb') as file:
            res = client.scan_file(file, wait_for_completion=True).to_dict()
        antivirus_results = res['attributes']['results']
        p.terminate()
        print('Сканируем полученный файл...' + bcolors.ENDC)
        print(bcolors.OKGREEN + 'Готово' + bcolors.ENDC)
        print(bcolors.BOLD + 'Проверяем результаты...' + bcolors.ENDC)
        dct = {}
        for i in antivirus_results:
            if antivirus_results[i]['result'] is not None:
                dct[i] = antivirus_results[i]
        if dct:
            print(bcolors.FAIL + 'В файле обнаружены вирусы или трояны!\n' + bcolors.ENDC)
            print(bcolors.UNDERLINE + 'Антивирус: Тип вируса/трояна' + bcolors.ENDC)
            for i in dct:
                print(bcolors.OKGREEN + i + bcolors.ENDC + ': ' + bcolors.FAIL + dct[i]['result'] + bcolors.ENDC)
        else:
            print(bcolors.OKGREEN + 'В файле не обнаружены вирусы!' + bcolors.ENDC)

        client.close()
    except:
        print(bcolors.FAIL + 'Произошла ошибка!')
        print(traceback.format_exc() + bcolors.ENDC)
    print()
    input('Press Enter to continue...')
