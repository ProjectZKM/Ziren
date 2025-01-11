# Circle STARK 

Circle STARK utilizes Mersenne prime M31
\\( p = 2^{31} - 1 \\)
and its extension field \\( F_{p^2} = \\{(x,y): x,y \in F_p\\} \\) as fundamental components . The choice of M31 is based on its small bit width and the simplicity of modular arithmetic, which makes it well-suited for algebraic operations on modern CPU and GPU architectures.

The multiplication in
\\( F_{p^{2}} \\),
is defined as \\( (x_1,y_1) \cdot (x_2,y_2) = (cdx_1x_2-y_1y_2, x_1y_2 + x_2y_1) \\).  The multiplicative group \\( F_{p^2}  \setminus \\{0,0\\} \\) has an order of \\( p^2 - 1 = 2^{31}\cdot (2^{31}-2) \\), and there exists a cyclic subgroup of order \\( 2^{31} \\) given by \\( \mathbb{C} = \\{(x,y) : x^2 + y^2 = 1, x,y \in F_p\\} \\).

## The "polynomials" in circle STARK

The "polynomials" considered in circle STARK take the form

\\( L_N(F) = \\{p(x,y) \in F(x,y) /(x^2 + y^2 -1) : deg(p) \leq N/2\\} \\), where \\( F= F_{p^2} \\).

Here, the domain of \\( p(x,y) \\) is \\( P= (x,y) \in F \\). The term "polynomial" here refers to the result after taking the quotient by \\( x^2+y^2=1 \\). This means we can always express \\( p(x,y) \\) as \\( a_0 + a_1 x + a_2 x^2 + ... + a_{N/2}x^{N/2} + y(b_0 + b_1 x + b_2 x^2 + ... + b_{N/2-1}x^{N/2-1}) \\) with \\( a_i, b_i \in F \\).

## Domain in circle STARK

When dealing with elements in \\( L_N(F) \\) , we require that the number of elements in the selected domain be \\( N=2^n \\), and that there exists an easily representable "\\( 2\rightarrow 1 \\)" mapping to facilitate the iteration \\( G_n \rightarrow G_{n-1} \rightarrow   \cdots \rightarrow G_1 \rightarrow G_0 \\), with \\( |G_i| = 2^i \\). 

Let \\( g \\) be a generator of \\( \mathbb{C} \\), and denote \\( g_n = g^{2^{31-n}} \\), then \\( D_n = (g_n) \\) is a subgroup of order \\( 2^{n} \\). Circle STARK uses \\( G_n = g_{n+1} D_{n} \\), a coset of \\( D_n \\) as the initial domain. 

In the first iteration, we perform the mapping \\( G_n \rightarrow G_{n-1} : (x,y) \rightarrow x \\).

Subsequent iterations are defined by the mapping  \\( G_i \rightarrow G_{i-1}: x \rightarrow 2x^2-1 \\) (recall \\( (x,y) \cdot (x,y) = (2x^2-1, 2xy) \\), the mapping corresponds to multiply a point by itself).

 (Note: The reason for not directly selecting \\( G_n = D_n \\) is to simplify the subsequent FFT/FRI recursive operations.)

## Construction of Recursive Operations

Consider \\( F(x,y) \in  \mathbb{L}_N(\mathbb{F}) \\), Taking the FFT decomposition as an example, we can outline the steps as follows.

First step of decomposition: 

\\( F(x,y) = f_0(x) + y f_1(x) \\), or equally 
 \\( f_0(x) = \frac{F(x,y) + F(x,-y)}{2}, f_1(x) = \frac{F(x,y) - F(x,-y)}{2y} \\).

Second step of decomposition：

\\( f_i(x) = f_{i,0}(2x^2-1) + xf_{i,1}(2x^2-1) \\) for \\( i = 0, 1\\), that is, \\( f_{i,0}(2x^2-1) = \frac{f_i(x) + f_i(-x)}{2}, f_{i,1}(x^2-1) = \frac{f_i(x) - f_i(-x)}{2x} \\).

We then repeat the second step of decomposition iteratively until we reach constant polynomials.

notes：

- Each iteration corresponds to a change in the domain:  \\( G_n \rightarrow G_{n-1} \rightarrow   \cdots \rightarrow G_1 \rightarrow G_0 \\). Starting from the second step, we use the mapping \\( \pi(x) = 2x^2-1 \\) instead of the \\( x^2 \\) in traditional FFT, which corresponds to the transformation \\( (x,y)\cdot (x,y) = (2x^2-1, 2xy) \\), reflecting the change in the \\( x- \\) coordinate. 

- The efficiency of FFT in rapidly computing polynomial coefficients from point-value representation arises from the fact that after polynomial decomposition, the set of coefficients in the lower-degree polynomials remains consistent with the set of coefficients in the original polynomial. To achieve this, we utilize the polynomial basis:

  \\( \\{1,x,y,x \cdot y,\pi(x),x \cdot \pi(x),y \cdot \pi(x),x \cdot y \cdot \pi(x),\pi(\pi(x)),x \cdot \pi(\pi(x)),y \cdot \pi(\pi(x))...\\} \\) (where \\( \pi(x) = 2x^2 - 1 \\)).

- When computing FRI, the decomposition method remains the same; however, the two polynomials obtained from each step of decomposition are combined linearly to form a single polynomial. So we only need to decompose one polynomial at each step in FRI. 

## An example of calculating circle FFT

Let's take \\( p = 31, n = 3, N = 2^n = 8 \\) as an example to explain the computation process of Circle FFT. The circle we consider is \\( \mathbb{C} = \\{(x,y): x^2 + y^2 = 1, x,y \in F_{15}\\} \\). We choose a generator \\( g = (5, 10) \\), then the elements \\( g^0, g, g^2, g^3, \cdots, g^{31} \\) are calculated as follows: \\( (1,0),(5,10),(18,7),(20,29),(27,4),(2,11),(24,13),(21,26),\\) \\( (0,30),(10,26),(7,13),(29,11),(4,4),(11,29),(13,7),(26,10),\\) \\( (30,0),(26,21),(13,24),(11,2),(4,27),(29,20),(7,18),(10,5), \\) \\( (0,1),(21,5),(24,18),(2,20),(27,27),(20,2),(18,24),(5,21) \\).

To compute polynomials in \\( L_8(F_{15^2}) \\), we have  \\( g_4 = g^2 = (18,7) \\), and  \\( D_3 = \\{g^0,g^4,g^8,g^{12},g^{16},g^{20},g^{24},g^{28} \\} \\). The initial domain selected for FFT is:

\\( S_3 = g_4 D_3 = \\{g^2, g^6, g^{10}, g^{14}, g^{18}, g^{22}, g^{26}, g^{30}\\} = \\\ \\{(18,7),(24,13),(7,13),(13,7),(13,24),(7,18),(24,18),(18,24)\\}. \\)

The compression of the domains is \\( S_3 \xrightarrow{\text{eliminating y}} S_2 = \\{18, 24, 7, 13\\} \xrightarrow{\pi(x) = 2x^2+1} S_1 = \\{27, 4\\} \xrightarrow{\pi(x)} s_0 = \\{0\\} \\).

Assume the polynomial to be solved is  \\( F(x,y) = a_0 + a_1 x + a_2 y + a_3 xy + a_4\pi(x) + a_5x \cdot \pi(x) + a_6y \cdot \pi(x) + a_7xy \cdot \pi(x) \\) with coefficients \\( a_0, a_1, \cdots, a_7\\) to be solved. We suppose its values on the domain \\(S_3\\) are sequentially \\( 1,2,3,4,5,6,7,8 \\) ( for simplicity, we use values in \\( F_{31} \\) instead of in \\( F_{31^2}\\) ). 

The first step of the decomposition:

\\( f_0(x) = \frac{F(x,y) + F(x,-y)}{2} = a_0 + a_1x +a_4 \pi(x) + a_5 x\pi(x),\\)

\\( f_1(x) = \frac{F(x,y) - F(x,-y)}{2y} = a_2 + a_3x + a_6 \pi(x) + a_7x\pi(x). \\)

Substituting the values of  \\( F(x,y) \\), we have:
\\[ f_0(18) = \frac{F(18, 7) + F(18, 24)}{2} = (1+8)/2 = 20, f_1(18) = \frac{1-8}{2 \cdot 7} = = 15. \\]

Similarly, \\( f_0(24) = 20 , f_0(7) = 20, f_0(13) = 20;\\) \\( f_1(24) = 1, f_1(7) = 15 , f_1(13) = 11\\).

The second step of the decomposition:

\\( f_{00}(\pi(x)) = \frac{f_0(x) + f_0(-x)}{2} = a_0 + a_4 \pi(x), f_{01}(\pi(x)) = \frac{f_0(x)-f_0(-x)}{2x} = a_1 + a_5\pi(x) \\),

\\( f_{10}(\pi(x)) = \frac{f_1(x) + f_1(-x)}{2} = a_2 + a_6 \pi(x), f_{11}(\pi(x)) = \frac{f_1(x)-f_1(-x)}{2x} = a_3 + a_7\pi(x). \\)

Based on the values of \\( f_0(\cdot)\\)  and \\( f_1(\cdot)\\) on \\( S_2 \\), we can calculate the values of \\( f_{00}(\cdot), f_{01}(\cdot), f_{10}(\cdot), f_{11}(\cdot)\\) on \\( S_1 \\):

\\( f_{00}(27) = \frac{f_0(18)+f_0(13)}{2} = 20, f_{00}(4) = \frac{f_0(24)+f_0(7)}{2} = 20 \\),

\\( f_{01}(27) = \frac{f_0(18) - f_0(13)}{2 \cdot 18} = 0, f_{01}(4) = \frac{f_0(24) - f_0(7)}{2 \cdot 24} = 0,\\)

\\( f_{10}(27) = \frac{f_1(18)+f_1(13)}{2} = 13, f_{10}(4) = \frac{f_1(24)+f_1(7)}{2} = 8,\\)

\\( f_{11}(27) = \frac{f_1(18) - f_1(13)}{2 \cdot 18} = 7, f_{11}(4) = \frac{f_1(24) - f_1(7)}{2 \cdot 24} = 1.\\)

 The third step of decomposition：

\\( f_{000}(\pi(x)) = \frac{f_{00}(x) + f_{00}(-x)}{2} = a_0, f_{001}(\pi(x)) = \frac{f_{00}(x)-f_{00}(-x)}{2x} = a_4,\\)

\\( f_{010}(\pi(x)) = \frac{f_{01}(x) + f_{01}(-x)}{2} = a_1, f_{011}(\pi(x)) = \frac{f_{01}(x)-f_{01}(-x)}{2x} = a_5,\\)

\\( f_{100}(\pi(x)) = \frac{f_{10}(x) + f_{10}(-x)}{2} = a_2, f_{101}(\pi(x)) = \frac{f_{10}(x)-f_{10}(-x)}{2x} = a_6,\\)

\\( f_{110}(\pi(x)) = \frac{f_{11}(x) + f_{11}(-x)}{2} = a_3, f_{111}(\pi(x)) = \frac{f_{11}(x)-f_{11}(-x)}{2x} = a_7.\\)

Based on the values of \\( f_{00}(\cdot), f_{01}(\cdot), f_{10}(\cdot), f_{11}(\cdot)\\) on \\(S_1\\), we have:

\\( f_{000}(0) = \frac{f_{00}(27) + f_{00}(4)}{2} = 20, f_{001}(0) = \frac{f_{00}(27)-f_{00}(4)}{2*27} = 0,\\)

\\( f_{010}(0) = \frac{f_{01}(27) + f_{01}(4)}{2} = 0, f_{011}(0) = \frac{f_{01}(27)-f_{01}(4)}{2*27} = 0,\\)

\\( f_{100}(0) = \frac{f_{10}(27) + f_{10}(4)}{2} = 26, f_{101}(0) = \frac{f_{10}(27)-f_{10}(4)}{2*27} = 11,\\)

\\( f_{110}(0) = \frac{f_{11}(27) + f_{11}(4)}{2} = 4, f_{111}(0) = \frac{f_{11}(27)-f_{11}(4)}{2*27} = 7.\\)

Thus, we obtain:\\( F(x,y) = 20 + 0 x + 26 y + 4 xy + 0 \pi(x) + 0 x \cdot \pi(x) + 11y \cdot \pi(x) + 7xy \cdot \pi(x).\\)

It is noted that in each step of calculating \\( f_{*0}(x)\\) and \\( f_{*1}(x)\\)，we need to perforn one multiplication ( \\( \times \frac{1}{2y} \\) or \\( \times \frac{1}{2x} \\)) and two additions, leading to an overall time complexity of \\( n \cdot 2^n(\frac{1}{2} \cdot Mul + 1 \cdot Add) \\).

## revealing polynomial values 

In the circle STARK protocol, we prove that \\( v_1 = F(x_1,y_1) \\), where  \\( F(x,y) \in \mathbb{L}_N(\mathbb{F})\\) , using the following method:

Select any point  \\( (x_2,y_2) \\) such that \\(x_2 \neq x_1 \\) and \\( y_2 \neq y_1 \\), and suppose \\( v_2 = F(x_2,y_2) \\). Denote the line through the points \\( (x_1,y_1), (x_2,y_2) \\) as \\( ax+by+c = 0 \\), and denote \\( L(x,y) = ax+by+c \\). The interpolation through the points \\( (y_1,v_1), (y_2,v_2)\\) is given by \\( I(y):v_1+(v_2-v_1)\frac{y-y_1}{y_2-y_1} \\). Then \\( v_1 = F(x_1,y_1) \\) is equivalent to saying that  \\( \frac{F(x,y)-I(y)}{L(x,y)}\\) is a polynomial. 

Explanition note：If exists \\( H(x,y) \\), such that \\( F(x,y)-I(y) = H(x,y)L(x,y) \\), then \\( v_1 = F(x_1,y_1) \\). Conversely, if \\( v_1 = F(x_1,y_1) \\) and \\( v_2 = F(x_2,y_2) \\), by selecting \\( N-2 \\) points do not lie on the line \\( L(x,y) = 0 \\) ,  the values of these $N-2$ points on \\( \frac{F(x,y)-I(y)}{L(x,y)} \\) uniquely determine \\( H(x,y) \in \mathbb{L}_{N-1}(F) \\).
