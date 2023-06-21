template<typename T>
void delete_buffers(T* buffer) {
    delete[] buffer;
}

template<typename T, typename... Ts>
void delete_buffers(T* buffer, Ts*... buffers) {
    delete[] buffer;
    delete_buffers(buffers...);
}