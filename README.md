In-Memory Fuzzer, основанный на PIN.

ОС: Windows x86 (поддержка x64 будет реализована далее)

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

-track <cfg_file.txt> -- Программа получает на вход значения и отслеживает
обращения к ячейкам памяти, содержащим такие значения. Пример конфигурационного
файла (cfg_file.txt) расположен в 'Config Examples\trace.txt'

-trace <cfg_file.txt> -- Отслеживание посещений базовых блоков в пределах 
заданных образов. В конфигурационном файле (cfg_file.txt) приводится список
всех образов, которые необходимо обработать, название каждого образа
(полный путь к нему) записывается с новой строки.

-fuzz <cfg_file.txt> -- Фаззинг заданных функций и диапазонов инструкций,
заданных в конфигурационном файле (cfg_file.txt). Пример конфигурационного
файла расположен в 'Config Examples\fuzzing.txt' (НЕ РАБОТАЕТ)

!!!
Весь представленный код пока что находится в стадии разработки.
Некоторые функции пока нереализованы. Возможно наличие ошибок.
!!!

--------------------------------------------------------------

OS: Windows x86 (x64 support is comming soon)

The project is analysis tool which purpose is error detection by fuzzing.

Build and compile:
Download PIN from official site then put the project in directory
%PIN_root_dir%\source\tools. Use Microsoft Visual Studio to build and compile.

Run:
pin.exe -t path\to\FuzzingPinTool.dll <options> -- program.exe

General output file is "outdata.txt" located in launch directory.

Options:

-outline -- Output of a list of all images and included routines

-test <cfg_file.txt> -- Routines and instruction ranges test review;
It allows to disassembly, to read values stored in memory and processor context
on specific instructions. Configuration file example is stored in: 'Config Examples\test.txt'

-track <cgf_file.txt> -- The tool receives input values and monitors (tracks) 
accesing to the memory cells which contains such values.
Configuration file example is stored in: 'Config Examples\track.txt'

-trace <cfg_file.txt> -- BBL visits monitoring in specified images.
Configuration file is list of images names, where each name begins
with new line.

-fuzz <cfg_file.txt> -- Specified routines and instructions ranges fuzzing.
Configuration file example is stored in: 'Config Examples\fuzzing.txt'

!!!
The project is under development. Some functions and scopes aren't implemented.
Errors are possible.
!!!