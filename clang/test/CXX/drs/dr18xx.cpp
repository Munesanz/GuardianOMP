// RUN: %clang_cc1 -std=c++98 -triple x86_64-unknown-unknown %s -verify -fexceptions -Wno-deprecated-builtins -fcxx-exceptions -pedantic-errors
// RUN: %clang_cc1 -std=c++11 -triple x86_64-unknown-unknown %s -verify -fexceptions -Wno-deprecated-builtins -fcxx-exceptions -pedantic-errors
// RUN: %clang_cc1 -std=c++14 -triple x86_64-unknown-unknown %s -verify -fexceptions -Wno-deprecated-builtins -fcxx-exceptions -pedantic-errors
// RUN: %clang_cc1 -std=c++17 -triple x86_64-unknown-unknown %s -verify -fexceptions -Wno-deprecated-builtins -fcxx-exceptions -pedantic-errors
// RUN: %clang_cc1 -std=c++20 -triple x86_64-unknown-unknown %s -verify -fexceptions -Wno-deprecated-builtins -fcxx-exceptions -pedantic-errors
// RUN: %clang_cc1 -std=c++2b -triple x86_64-unknown-unknown %s -verify -fexceptions -Wno-deprecated-builtins -fcxx-exceptions -pedantic-errors

#if __cplusplus < 201103L
// expected-error@+1 {{variadic macro}}
#define static_assert(...) __extension__ _Static_assert(__VA_ARGS__)
#endif

namespace dr1813 { // dr1813: 7
  struct B { int i; };
  struct C : B {};
  struct D : C {};
  struct E : D { char : 4; };

  static_assert(__is_standard_layout(B), "");
  static_assert(__is_standard_layout(C), "");
  static_assert(__is_standard_layout(D), "");
  static_assert(!__is_standard_layout(E), "");

  struct Q {};
  struct S : Q {};
  struct T : Q {};
  struct U : S, T {};

  static_assert(__is_standard_layout(Q), "");
  static_assert(__is_standard_layout(S), "");
  static_assert(__is_standard_layout(T), "");
  static_assert(!__is_standard_layout(U), "");
}

namespace dr1814 { // dr1814: yes
#if __cplusplus >= 201103L
  void test() {
    auto lam = [](int x = 42) { return x; };
  }
#endif
}

namespace dr1815 { // dr1815: no
#if __cplusplus >= 201402L
  // FIXME: needs codegen test
  struct A { int &&r = 0; }; // expected-note {{default member init}}
  A a = {}; // FIXME expected-warning {{not supported}}

  struct B { int &&r = 0; }; // expected-error {{binds to a temporary}} expected-note {{default member init}}
  B b; // expected-note {{here}}
#endif
}

namespace dr1821 { // dr1821: yes
struct A {
  template <typename> struct B {
    void f();
  };
  template <typename T> void B<T>::f(){};
  // expected-error@-1 {{non-friend class member 'f' cannot have a qualified name}}

  struct C {
    void f();
  };
  void C::f() {}
  // expected-error@-1 {{non-friend class member 'f' cannot have a qualified name}}
};
} // namespace dr1821

namespace dr1822 { // dr1822: yes
#if __cplusplus >= 201103L
  int a;
  auto x = [] (int a) {
#pragma clang __debug dump a // CHECK: ParmVarDecl
  };
#endif
}

namespace dr1837 { // dr1837: 3.3
#if __cplusplus >= 201103L
  template <typename T>
  struct Fish { static const bool value = true; };

  struct Other {
    int p();
    auto q() -> decltype(p()) *;
  };

  class Outer {
    friend auto Other::q() -> decltype(this->p()) *; // expected-error {{invalid use of 'this'}}
    int g();
    int f() {
      extern void f(decltype(this->g()) *);
      struct Inner {
        static_assert(Fish<decltype(this->g())>::value, ""); // expected-error {{invalid use of 'this'}}
        enum { X = Fish<decltype(this->f())>::value }; // expected-error {{invalid use of 'this'}}
        struct Inner2 : Fish<decltype(this->g())> { }; // expected-error {{invalid use of 'this'}}
        friend void f(decltype(this->g()) *); // expected-error {{invalid use of 'this'}}
        friend auto Other::q() -> decltype(this->p()) *; // expected-error {{invalid use of 'this'}}
      };
      return 0;
    }
  };

  struct A {
    int f();
    bool b = [] {
      struct Local {
        static_assert(sizeof(this->f()) == sizeof(int), "");
      };
    };
  };
#endif
}

namespace dr1872 { // dr1872: 9
#if __cplusplus >= 201103L
  template<typename T> struct A : T {
    constexpr int f() const { return 0; }
  };
  struct X {};
  struct Y { virtual int f() const; };
  struct Z : virtual X {};

  constexpr int x = A<X>().f();
  constexpr int y = A<Y>().f();
#if __cplusplus <= 201703L
  // expected-error@-2 {{constant expression}} expected-note@-2 {{call to virtual function}}
#else
  static_assert(y == 0);
#endif
  // Note, this is invalid even though it would not use virtual dispatch.
  constexpr int y2 = A<Y>().A<Y>::f();
#if __cplusplus <= 201703L
  // expected-error@-2 {{constant expression}} expected-note@-2 {{call to virtual function}}
#else
  static_assert(y == 0);
#endif
  constexpr int z = A<Z>().f(); // expected-error {{constant expression}} expected-note {{non-literal type}}
#endif
}

namespace dr1881 { // dr1881: 7
  struct A { int a : 4; };
  struct B : A { int b : 3; };
  static_assert(__is_standard_layout(A), "");
  static_assert(!__is_standard_layout(B), "");

  struct C { int : 0; };
  struct D : C { int : 0; };
  static_assert(__is_standard_layout(C), "");
  static_assert(!__is_standard_layout(D), "");
}

void dr1891() { // dr1891: 4
#if __cplusplus >= 201103L
  int n;
  auto a = []{}; // expected-note 0-4{{}}
  auto b = [=]{ return n; }; // expected-note 0-4{{}}
  typedef decltype(a) A;
  typedef decltype(b) B;

  static_assert(!__has_trivial_constructor(A), "");
#if __cplusplus > 201703L
  // expected-error@-2 {{failed}}
#endif
  static_assert(!__has_trivial_constructor(B), "");

  // C++20 allows default construction for non-capturing lambdas (P0624R2).
  A x;
#if __cplusplus <= 201703L
  // expected-error@-2 {{no matching constructor}}
#endif
  B y; // expected-error {{no matching constructor}}

  // C++20 allows assignment for non-capturing lambdas (P0624R2).
  a = a;
  a = static_cast<A&&>(a);
#if __cplusplus <= 201703L
  // expected-error@-3 {{copy assignment operator is implicitly deleted}}
  // expected-error@-3 {{copy assignment operator is implicitly deleted}}
#endif
  b = b; // expected-error {{copy assignment operator is implicitly deleted}}
  b = static_cast<B&&>(b); // expected-error {{copy assignment operator is implicitly deleted}}
#endif
}

namespace dr1894 { // dr1894: 3.8
                   // NB: reusing part of dr407 test
namespace A {
  struct S {};
}
namespace B {
  typedef int S;
}
namespace E {
  typedef A::S S;
  using A::S;
  struct S s;
}
namespace F {
  typedef A::S S;
}
namespace G {
  using namespace A;
  using namespace F;
  struct S s;
}
namespace H {
  using namespace F;
  using namespace A;
  struct S s;
}
}
