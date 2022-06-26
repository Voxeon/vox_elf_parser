__attribute__((force_align_arg_pointer)) void _start()
{
    int a = 52;
    int b = 23;
    int c = a * b + a + b;

    __builtin_unreachable();
}