In-Memory Fuzzer, основанный на PIN.

ОС: Windows x86

Данный проект представляет собой средство анализа исполняемых файлов
и последующего фаззинга кода с целью выявления ошибок.

Реализовано строго для ОС Windows с 32-битной архитектурой.

Для сборки скачайте PIN с официального сайта и поместите проект в директорию
%PIN_root_dir%\source\tools

Запуск:
pin.exe -t path\to\FuzzingPinTool.dll <options> -- program.exe

Весь вывод данного фаззера будет представлен в файле outdata.txt,
расположение которого зависит от того, относительно какой директории
выполняется запуск PIN

Опции:

-outline -- Вывод списка всех образов и содержащихся в них функций

-test <cfg_file.txt> -- Тестовый обзор исполняемых инструкций,
позволяет диассемблировать функции, диапазоны инструкций, 
читать значения из памяти и значения регистров 
на определенных инструкциях. Пример конфигурационного файла (cfg_file.txt)
расположен в 'Config Examples\test.txt'

-trace <cfg_file.txt> -- Программа получает на вход значения и отслеживает
обращения к ячейкам памяти, содержащим такие значения. Пример конфигурационного
файла (cfg_file.txt) расположен в 'Config Examples\trace.txt'

-track <cfg_file.txt> -- Отслеживание посещений базовых блоков в пределах 
заданных образов. В конфигурационном файле (cfg_file.txt) приводится список
всех образов, которые необходимо обработать, название каждого образа
(полный путь к нему) записывается с новой строки.

-fuzz <cfg_file.txt> -- Фаззинг заданных функций и диапазонов инструкций,
заданных в конфигурационном файле (cfg_file.txt). Пример конфигурационного
файла расположен в 'Config Examples\fuzzing.txt'

!!!
Весь представленный код пока что находится в стадии тестовой версии.
Некоторые функции пока нереализованы. Возможно наличие ошибок.
!!!