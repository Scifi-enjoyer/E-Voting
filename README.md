# Demo bỏ phiếu điện tử với thuật toán Rabin

## Cấu trúc thư mục
rabin_voting/
├──elections # Chứa cấu hình của các cuộc bầu cử(thiết lập bởi authority qua giao diện)
├── interface/
│ ├──gui_authority.py # Giao diện bên kiểm phiếu 
│ ├──gui_voter.py # Giao diện bên cử tri
├── src/
│ ├── utils_rabin.py # Thư viện Rabin (số học, ký, verify, mã hóa/giải mã)
│ ├── voter.py # Mô phỏng cử tri
│ ├── authority.py # Mô phỏng kiểm phiếu
├── keys/
│ ├── authority/ # Chứa khóa Authority (auth_priv.json, auth_pub.json)
│ └── voters/ # Chứa khóa(priv) của riêng từng voter
├── votes/ # Chứa các file phiếu bầu (vote_xxx.json)
├── package_plain  # chứa package gốc chưa mã hóa
├── votes_approved # chứa votes qua kiểm phiếu và được công nhận là phiếu đúng/hợp lệ
├── votes_not_approved # chứa votes qua kiểm phiếu và được xác nhận là phiếu sai/không hợp lệ
└── config.py # Cấu hình thư mục (keys, votes, ...)

## Hướng dẫn chạy thử

***Lần đầu tiên chạy chương trình: Chạy file config.py để sinh folder keys,package_plain,votes,votes_approved,vote_not_approved

*CÁC BƯỚC CHẠY CHƯƠNG TRÌNH:
    BƯỚC 1: Chạy interface/gui_authority.py -> Bấm sinh khóa và tạo cấu hình(config) cho bầu cử 
    BƯỚC 2: Chạy interface/gui_voter.py
        ──>Chương trình sẽ tạo ra phiếu theo định dạng .JSON để trong mục votes
    BƯỚC 3: Trong giao diện bên kiểm phiếu thực hiện kiểm phiếu
        ──>Chương trình sẽ thực hiện kiểm phiếu và đưa phiếu vào 1 trong 2 mục: votes_approved(nếu hợp lệ) hoặc votes_not_approved(nếu không hợp lệ)
    BƯỚC 4: Tổng hợp kết quả phiếu trên giao diện bên kiểm phiếu
        ──>Chương trình sẽ thực hiện qua trình quét qua 2 mục votes_approved và votes_not_approved và tổng hợp kết quả số phiếu trong mục Log
    Kết thúc quá trình mô phỏng(kết thúc chương trình)