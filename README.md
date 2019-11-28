1. Sửa host và API Token trong code:

*  Đường dẫn: *sigma/tools/sigma/backends/carbonblack.py* - line 145.

> url = host CarbonBlack 


> X-Auth-Token = API Token từ profile admin


2. Chạy lệnh gọi chuyển rules lên watchlist qua API:
 

    **cd /sigma/tools**
    

    **python3 sigmac -t carbonblack -c carbonblack -r <rule directory>**

Example:
    
    **python3 sigmac  -t carbonblack -c carbonblack -r ../rules/windows/process_creation**
