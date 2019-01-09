
'''
deneme2 = "deneme Sat Jan  5 23:19:02 2019"
deneme = "Sat Jan  5 23:19:02 2019"

print(deneme[-24:])
print(deneme2.split("."))'''

sayac = 0
n = eval(input("sayi giriniz: "))
while(True):
    if n == 1:
        break
    n = int(n/2)
    sayac = sayac + 1
print(sayac)