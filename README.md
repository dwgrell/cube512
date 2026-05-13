# Cube512 — 512-битный блочный шифр

Алгоритм основан на 3D-кубе 8×8×8 битов.  
Каждый раунд: XOR + сдвиги по осям X → Y → Z на 3 или 5 позиций (зависит от popcount).

## Сборка

```bash
sudo apt install build-essential libssl-dev libarchive-dev liblz4-dev
make
