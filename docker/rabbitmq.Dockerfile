FROM rabbitmq:3.12-management-alpine

# RabbitMQ requires messages to be acked in 30 minutes or else it will mark
# a client as stale. This conflicts with Celery tasks that have a countdown
# or eta set beyond 30 minutes as they are not acked before this time. Setting
# this timeout to 1 year here to work around this issue.
# Related error and info:
# amqp.exceptions.PreconditionFailed: (0, 0): (406) PRECONDITION_FAILED - consumer ack timed out on channel 1
# https://github.com/celery/celery/issues/6760
RUN echo "consumer_timeout = 31622400000" >> /etc/rabbitmq/rabbitmq.conf