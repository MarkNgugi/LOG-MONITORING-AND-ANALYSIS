import pika

# RabbitMQ connection information from CloudAMQP
amqp_url = 'amqps://yzlnsvqt:QbZqmgDYeXTxeXyzftLzWcG_he_Nsgq7@shrimp.rmq.cloudamqp.com/yzlnsvqt'

# Test connection to RabbitMQ
def test_rabbitmq_connection():
    try:
        # Parse AMQP URL to connection parameters
        params = pika.URLParameters(amqp_url)

        # Establish connection
        connection = pika.BlockingConnection(params)
        channel = connection.channel()

        # Declare a queue (creates it if it doesn't exist)
        queue_name = 'test_queue'
        channel.queue_declare(queue=queue_name)

        # Send a test message to the queue
        test_message = 'Hello, RabbitMQ! This is a test message.'
        channel.basic_publish(exchange='',
                              routing_key=queue_name,
                              body=test_message)

        print(f"Test message sent: {test_message}")

        # Close the connection
        connection.close()

    except Exception as e:
        print(f"Failed to connect or send message: {e}")

# Run the connection test
if __name__ == '__main__':
    test_rabbitmq_connection()
