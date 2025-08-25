import sys

MOD=998244353
n=int(sys.stdin.readline().strip())

best_k=None
best_d=None
for d in range(1,10):
    rem=0
    for k in range(1,n+1):
        rem=(rem*10+d)%n
        if rem==0:
            if best_k is None or k<best_k or (k==best_k and d<best_d):
                best_k=k
                best_d=d
            break

if best_k is None:
    print(-1)
else:
    ans=0
    for _ in range(best_k):
        ans=(ans*10+best_d)%MOD
    print(ans)
