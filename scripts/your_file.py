MOD=998244353
inv=pow(2,-1,MOD)
print(inv)
ns=[]
t=int(input())
for _ in range(t):
    ns.append(int(input()))
def C2(x):
    return (x*(x-1))%MOD*inv%MOD

out=[]
for n in ns:
    a=(n+1)//2
    b=n//2
    A=a*a%MOD
    B=a*b%MOD
    C=B
    D=b*b%MOD
    ans=(C2(A)*B%MOD*C%MOD*D + C2(B)*A%MOD*C%MOD*D + C2(C)*A%MOD*B%MOD*D + C2(D)*A%MOD*B%MOD*C)%MOD
    out.append(str(ans))
print("\n".join(out))
