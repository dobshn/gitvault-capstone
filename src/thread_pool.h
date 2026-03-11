// thread_pool.h
#pragma once
#include <vector>
#include <queue>
#include <thread>
#include <future>
#include <mutex>
#include <condition_variable>
#include <functional>

class ThreadPool {
public:
    explicit ThreadPool(size_t thread_count)
        : stop(false)
    {
        for (size_t i = 0; i < thread_count; ++i) {
            workers.emplace_back([this]() {
                for (;;) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(mutex);
                        cv.wait(lock, [this]() {
                            return stop || !tasks.empty();
                        });

                        if (stop && tasks.empty())
                            return;

                        task = std::move(tasks.front());
                        tasks.pop();
                    }

                    task();
                }
            });
        }
    }

    template <class F>
    std::future<void> enqueue(F&& f)
    {
        auto task = std::make_shared<std::packaged_task<void()>>(std::forward<F>(f));

        std::future<void> result = task->get_future();

        {
            std::lock_guard<std::mutex> lock(mutex);
            tasks.emplace([task]() { (*task)(); });
        }

        cv.notify_one();
        return result;
    }

    ~ThreadPool()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stop = true;
        }

        cv.notify_all();

        for (auto& t : workers)
            t.join();
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex mutex;
    std::condition_variable cv;
    bool stop;
};