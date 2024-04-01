# License-API
Задача: \
Разработка средства, реализующего механизмы лицензирования программного обеспечения (клиент-серверное приложение, где сервер лицензирования и клиентский код, внедряемый в защищаемое приложение). Реализация API для внедрения в код программ на различных языках программирования.

В данном проекте используется доступная библиотека Crypto++: https://www.cryptopp.com/ 

Проект Клиента выглядит следующим образом:\
![alt text](https://github.com/matematu4ka/License-API/blob/main/Клиент.png)\
Проект Сервера:\
![alt text](https://github.com/matematu4ka/License-API/blob/main/Сервер.png)

Механизм избегания повторного получения лицензии: \
Для решения данной задачи был придуман алгоритм, использующий системные команды наряду со скриптом PowerShell. Получаемые данные записывались в файл, а данные, хранимые в нем, парсились и передавались в оборот дальше. На стороне сервера ведется логирование каждого подключения, и в том числе серийных номеров подключаемых устройств, поэтому подмена ip не даст никакого результата. Таким образом, программа защищена он несанкционированного получения нескольких лицензий для одного пользователя. 

Результат работы:\
![alt text](https://github.com/matematu4ka/License-API/blob/main/Работа_программы.png)

Попытка получения лизензии второй раз:\
![alt text](https://github.com/matematu4ka/License-API/blob/main/Ошибка_получения_лицензии.png)
