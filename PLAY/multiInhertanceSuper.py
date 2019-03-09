class Person(object):
    def __init__(self):
        print 'I am a Person!'


class Chef(Person):
    def __init__(self):
        super(Chef, self).__init__()
        print 'I am a Chef!'

    def speak(self):
        print 'Chef speaking!'


class Teacher(Person):
    def __init__(self):
        super(Teacher, self).__init__()
        print 'I am a Teacher!'

    def speak(self):
        print 'Teacher speaking!'


# class Member(Chef, Teacher):
# def __init__(self):
#     super(Member, self).__init__()

def temp(self):
    super(Member, self).__init__()


# Member = type('Member', (Chef,Teacher), {'__init__': temp})
Member = type('Member', (Chef, Teacher), {})
# print issubclass(Member, Teacher)
# print issubclass(Member, Chef)
m = Member()
print Member.mro()