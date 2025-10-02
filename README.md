# Megascanner

- **В качестве компилятора использовал MinGW, поэтому билдим так:**
```bash
mkdir build
cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
```

- **После билда запускаем так:**
```bash
.\scanner.exe --base ..\base.csv --log ..\report.log --path C:\Users\YA_LUBLU_KASPERSKY\Desktop\kasperich2.0
```

- **В директорию testfiles накидал текстовых файлов для тестов. Хеши для них прописаны в base.csv**