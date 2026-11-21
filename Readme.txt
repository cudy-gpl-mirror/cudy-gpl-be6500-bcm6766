GPL code for  WR3600/WR3600H

Build WR6500 Guide:
1. cd ./21.02
2. make R89_oemconfig
3. make V=s -j4

Build WR6500E Guide:
1. cd ./21.02
2. make R88_oemconfig
3. make V=s -j4

Build WR6500H Guide:
1. cd ./21.02
2. make R79_oemconfig
3. make V=s -j4


Notice:
1. When you are tring to build GPL code, the make program will automatic download
   some other source code packages that it needs from Internet, please make sure 
   your Linux PC have good Internet connection.

2. If you are of the opinion that CUDY should offer further source code subject
   to the GPL, please contact us under 'support@cudy.com'.
