#ifndef IRODS_RING_BUFFER_HPP
#define IRODS_RING_BUFFER_HPP

#include <boost/circular_buffer.hpp>
#include "lock_and_wait_strategy.hpp"
#include <iterator>

namespace irods {
namespace experimental {

    // ring buffer with protection for overwrites
    template <typename T>
    class circular_buffer {

        public:

            explicit circular_buffer(
                const size_t capacity,
                std::unique_ptr<lock_and_wait_strategy> lws = std::make_unique<lock_and_wait>())
                : cb_{capacity}
                , lws_{std::move(lws)}
            {
            }

            explicit circular_buffer(
                const size_t capacity,
                int timeout)
                : circular_buffer(capacity, std::make_unique<lock_and_wait_with_timeout>(timeout))
            {
            }

            // Pop the front item from the queue into entry.
            // Returns true if exit_predicate is met in which case nothing is popped.
            //
            //   Note: exit_predicate is used to determine if reading is done and allows this
            //         determination to be done while the circular buffer is locked.  This is to
            //         avoid possible race conditions.
            bool pop_front(T& entry, std::function<bool()> exit_predicate = {})
            {
                bool exit_condition = false;

                (*lws_)([this, &exit_predicate, &exit_condition] {

                            if (exit_predicate) {
                                exit_condition = exit_predicate();
                            }
                            return 0 < cb_.size() || ( exit_condition );

                        },
                        [this, &entry, &exit_condition] {

                            if (!exit_condition) {
                                auto iter = cb_.begin();
                                entry = *iter;
                                cb_.pop_front();
                            }

                        } );

                return exit_condition;
            }

            // Erase n items from front of the queue.
            // Returns true if exit_predicate is met in which case nothing is popped.
            //
            //   Note: exit_predicate is used to determine if reading is done and allows this
            //         determination to be done while the circular buffer is locked.  This is to
            //         avoid possible race conditions.
            bool pop_front(size_t n, std::function<bool()> exit_predicate = {})
            {
                bool exit_condition = false;

                (*lws_)([this, n, exit_predicate, &exit_condition] {

                            if (exit_predicate) {
                                exit_condition = exit_predicate();
                            }

                            return n <= cb_.size() || exit_condition;
                        },

                        [this, n, &exit_condition] {

                            if (!exit_condition) {
                                cb_.erase_begin(n);
                            }

                        } );

                return exit_condition;

            }

            // Peek item at offset from beginning into entry without removing from queue.
            void peek(size_t offset, T& entry)
            {
                (*lws_)([this, offset] { return offset < cb_.size(); },
                        [this, offset, &entry] {
                            auto iter = cb_.begin();
                            entry = *(iter + offset);
                        } );
            }

            // Peek n items starting at offset (from beginning) into array without
            // removing from buffer.
            //
            //  precondition: array is large enough to hold n items.
            void peek(off_t offset, size_t n, T array[])
            {
                auto length = offset + n;
                (*lws_)([this, length] { return length <= cb_.size(); },
                        [this, offset, n, &array] {
                            auto iter = cb_.begin() + offset;
                            std::copy(iter, iter + n, array);
                        } );
            }

            // Push the items between begin and end to the circular buffer.
            // Returns the number of items pushed.
            //
            //   Note: post_push_work, if defined, is executed after the push while the circular
            //   buffer remains locked.  In some cases this may help avoid race conditions.
            template <typename iter>
            long push_back(iter begin, iter end, std::function<void()> post_push_work = {})
            {
                // push what you can, return the number pushed
                long insertion_count = 0;
                (*lws_)([this] { return cb_.size() < cb_.capacity(); },
                        [this, begin, end, post_push_work, &insertion_count] {

                            auto distance = static_cast<unsigned long>(std::distance(begin, end));
                            auto empty_space = cb_.capacity() - cb_.size();
                            insertion_count = ( empty_space < distance ? empty_space : distance );
                            cb_.insert(cb_.end(), begin, begin + insertion_count );

                            if (post_push_work) {
                                post_push_work();
                            }

                        } );

                return insertion_count;

            }

            // Push entry onto the circular buffer.
            //
            //   Note: post_push_work, if defined, is executed after the push while the circular
            //   buffer remains locked.  In some cases this may help avoid race conditions.
            void push_back(const T& entry, std::function<void()> post_push_work = {})
            {
                (*lws_)([this] { return cb_.size() < cb_.capacity(); },
                        [this, post_push_work, &entry] {
                            cb_.push_back(entry);
                            if (post_push_work) {
                                post_push_work();
                            }
                        } );
            }

            bool is_empty()
            {
                return 0 == cb_.size();
            }


        private:

            boost::circular_buffer<T> cb_;
            std::unique_ptr<lock_and_wait_strategy> lws_;

    }; // class circular_buffer

} // namespace experimental
} // namespace irods
#endif
