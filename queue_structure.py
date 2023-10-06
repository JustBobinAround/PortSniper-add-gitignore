# Implementing a queue to handle port input

class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class Queue:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0
    
    def isEmpty(self):
        return self.head == None
    
    def display(self):
        if self.isEmpty():
            return print("Queue is empty, nothing to display")
        else:
            current = self.head
            while current != None:
                print(current.data, end=" ")
                current = current.next
    
    def enqueue(self, data):
        node = Node(data)
        if self.isEmpty():
            self.head = node
            self.tail = node
            self.size += 1
        else:
            self.tail.next = node
            self.tail = node
            self.size += 1
    
    def dequeue(self):
        port = self.head.data
        self.head = self.head.next
        self.size += 1
        return port