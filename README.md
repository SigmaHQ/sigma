1. Sửa host và API Token trong code:
2. Đường dẫn "sigma/tools/sigma/backends/carbonblack.py" line 145.
3. Sửa url = host CarbonBlack
4. X-Auth-Token = API Token từ profile admin

2. Chạy lệnh gọi chuyển rules lên watchlist qua API:
    cd /sigma/tools:
        `python3 sigmac -t carbonblack -c carbonblack -r <rule directory>`
        Example
        `python3 sigmac  -t carbonblack -c carbonblack -r ../rules/windows/process_creation`