from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
import jwt
import bcrypt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/Udemy'
mongo = PyMongo(app)

SECRET_KEY = 'vinaydatta$@123'

def get_next_id(counter_name):
    counter = mongo.db.counters.find_one_and_update(
        {'_id': counter_name},
        {'$inc': {'sequence_value': 1}},
        return_document=True,
        upsert=True
    )
    return counter['sequence_value']

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = mongo.db.users.find_one({'userId': int(data['userId'])})
            if not current_user:
                raise jwt.InvalidTokenError
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


def instructor_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'instructor':
            return jsonify({'message': 'Access forbidden: Instructors only!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def student_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'student':
            return jsonify({'message': 'Access forbidden: Students only!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')
    role = data.get('role', 'student')  

    if not username or not email or not password:
        return jsonify({'message': 'Username, email, and password are required'}), 400

    if mongo.db.users.find_one({'email': email}):
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user_id = get_next_id('user_id')  

    result = mongo.db.users.insert_one({
        'userId': user_id,
        'username': username,
        'email': email,
        'password': hashed_password,
        'phone': phone,
        'role': role  
    })

    return jsonify({'message': 'Signup successful', 'userId': user_id}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'userId': str(user['userId']),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')

    return jsonify({'token': token, 'userId': str(user['userId'])})

@app.route('/api/courses', methods=['POST'])
@token_required
@instructor_required
def create_course(current_user):
    data = request.json
    title = data.get('title')
    description = data.get('description')
    category = data.get('category')
    price = data.get('price')
    duration = data.get('duration')

    if not title or not description or not category or price is None or not duration:
        return jsonify({'message': 'All fields are required'}), 400

    course_id = get_next_id('course_id')  

    result = mongo.db.courses.insert_one({
        'courseId': course_id,
        'title': title,
        'description': description,
        'category': category,
        'price': price,
        'duration': duration,
        'instructorId': current_user['userId']  
    })

    return jsonify({'courseId': course_id, 'message': 'Course created'}), 201


@app.route('/api/courses/<course_id>', methods=['GET'])
def read_course(course_id):
    course = mongo.db.courses.find_one({'courseId': int(course_id)})
    if not course:
        return jsonify({'message': 'Course not found'}), 404

    return jsonify({
        'courseId': course['courseId'],
        'title': course['title'],
        'description': course['description'],
        'category': course['category'],
        'price': course['price'],
        'duration': course['duration'],
        'instructorId': course.get('instructorId')  
    })

@app.route('/api/courses/<course_id>', methods=['PUT'])
@token_required
@instructor_required
def update_course(current_user, course_id):
    data = request.json
    title = data.get('title')
    description = data.get('description')
    category = data.get('category')
    price = data.get('price')
    duration = data.get('duration')

    update_fields = {}
    if title is not None:
        update_fields['title'] = title
    if description is not None:
        update_fields['description'] = description
    if category is not None:
        update_fields['category'] = category
    if price is not None:
        update_fields['price'] = price
    if duration is not None:
        update_fields['duration'] = duration

    if not update_fields:
        return jsonify({'message': 'No data provided for update'}), 400

    result = mongo.db.courses.update_one({'courseId': int(course_id), 'instructorId': current_user['userId']}, {'$set': update_fields})
    if result.matched_count == 0:
        return jsonify({'message': 'Course not found or you are not the instructor'}), 404

    return jsonify({'message': 'Course updated'})

@app.route('/api/courses/<course_id>', methods=['DELETE'])
@token_required
@instructor_required
def delete_course(current_user, course_id):
    result = mongo.db.courses.delete_one({'courseId': int(course_id), 'instructorId': current_user['userId']})
    if result.deleted_count == 0:
        return jsonify({'message': 'Course not found or you are not the instructor'}), 404

    return jsonify({'message': 'Course deleted'})

@app.route('/api/courses', methods=['GET'])
def search_courses():
    category = request.args.get('category')
    price_range = request.args.get('priceRange')

    min_price = 0
    max_price = 1e6  

    query = {}

    if category and price_range:
        try:
            min_price, max_price = map(float, price_range.split('-'))
            if min_price > max_price:
                return jsonify({'message': 'Minimum price cannot be greater than maximum price'}), 400
            query = {
                'category': category,
                'price': {'$gte': min_price, '$lte': max_price}
            }
        except ValueError:
            return jsonify({'message': 'Invalid price range format'}), 400
    elif category:
        query = {
            'category': category,
            'price': {'$gte': min_price, '$lte': max_price}
        }
    elif price_range:
        try:
            min_price, max_price = map(float, price_range.split('-'))
            if min_price > max_price:
                return jsonify({'message': 'Minimum price cannot be greater than maximum price'}), 400
            query = {
                'price': {'$gte': min_price, '$lte': max_price}
            }
        except ValueError:
            return jsonify({'message': 'Invalid price range format'}), 400
    else:
        query = {
            'price': {'$gte': min_price, '$lte': max_price}
        }

    print(f"MongoDB Query: {query}")

    courses = mongo.db.courses.find(query)

    results = []
    for course in courses:
        results.append({
            'courseId': str(course['courseId']),
            'title': course['title'],
            'description': course['description'],
            'category': course['category'],
            'price': course['price'],
            'duration': course['duration'],
            'instructorId': course.get('instructorId')
        })

    return jsonify(results)

@app.route('/api/enrollments', methods=['POST'])
@token_required
@student_required
def enroll_course(current_user):
    data = request.json
    print("Received JSON body:", data) 

    course_id = data.get('courseId')
    
    if course_id is None:
        return jsonify({'message': 'Course ID is required'}), 400

    try:
        course_id = int(course_id)  
    except ValueError:
        return jsonify({'message': 'Invalid course ID format'}), 400

    course = mongo.db.courses.find_one({'courseId': course_id})
    if not course:
        return jsonify({'message': 'Course not found'}), 404

    existing_enrollment = mongo.db.enrollments.find_one({
        'userId': current_user['userId'],
        'courseId': course_id
    })
    if existing_enrollment:
        return jsonify({'message': 'Already enrolled in this course'}), 400

    enrollment_id = get_next_id('enrollment_id')  

    result = mongo.db.enrollments.insert_one({
        'enrollmentId': enrollment_id,
        'userId': current_user['userId'],
        'courseId': course_id,
        'enrollmentDate': datetime.datetime.utcnow()
    })

    return jsonify({'enrollmentId': enrollment_id, 'message': 'Enrollment successful'}), 201


@app.route('/api/enrollments/<int:enrollment_id>', methods=['DELETE'])
@token_required
def delete_enrollment(current_user, enrollment_id):
   
    enrollment = mongo.db.enrollments.find_one({'enrollmentId': enrollment_id})
    if not enrollment:
        return jsonify({'message': 'Enrollment not found'}), 404


    if current_user.get('role') == 'student' and current_user['userId'] != enrollment['userId']:
        return jsonify({'message': 'Access forbidden: Cannot delete other user\'s enrollment'}), 403

   
    result = mongo.db.enrollments.delete_one({'enrollmentId': enrollment_id})
    if result.deleted_count == 0:
        return jsonify({'message': 'Enrollment not found'}), 404

    return jsonify({'message': 'Enrollment deleted'})



@app.route('/api/enrollments/<enrollment_id>', methods=['PUT'])
@token_required
def update_enrollment(current_user, enrollment_id):
    data = request.json
    enrollment_date = data.get('enrollmentDate')

    if enrollment_date is None:
        return jsonify({'message': 'Enrollment date is required'}), 400

    
    enrollment = mongo.db.enrollments.find_one({'enrollmentId': int(enrollment_id)})
    if not enrollment:
        return jsonify({'message': 'Enrollment not found'}), 404

    if current_user.get('role') == 'student' and current_user['userId'] != enrollment['userId']:
        return jsonify({'message': 'Access forbidden: Cannot update other user\'s enrollment'}), 403

    result = mongo.db.enrollments.update_one(
        {'enrollmentId': int(enrollment_id)},
        {'$set': {'enrollmentDate': enrollment_date}}
    )
    if result.matched_count == 0:
        return jsonify({'message': 'Enrollment not found'}), 404

    return jsonify({'message': 'Enrollment updated'})


@app.route('/api/assessments', methods=['POST'])
@token_required
@instructor_required
def create_assessment(current_user):
    data = request.json
    course_id = data.get('courseId')
    title = data.get('title')
    assessment_type = data.get('type')
    questions = data.get('questions')

    if not course_id or not title or not assessment_type or not questions:
        return jsonify({'message': 'Course ID, title, type, and questions are required'}), 400

    if assessment_type not in ['quiz', 'test']:
        return jsonify({'message': 'Invalid assessment type'}), 400

    assessment_id = get_next_id('assessment_id')  

    result = mongo.db.assessments.insert_one({
        'assessmentId': assessment_id,
        'courseId': int(course_id),
        'title': title,
        'type': assessment_type,
        'questions': questions
    })

    return jsonify({'assessmentId': assessment_id, 'message': 'Assessment created'}), 201


@app.route('/api/assessments/<int:assessment_id>', methods=['GET'])
def read_assessment(assessment_id):
    assessment = mongo.db.assessments.find_one({'assessmentId': assessment_id})
    if not assessment:
        return jsonify({'message': 'Assessment not found'}), 404

    return jsonify({
        'assessmentId': assessment['assessmentId'],
        'courseId': assessment['courseId'],
        'title': assessment['title'],
        'type': assessment['type'],
        'questions': assessment['questions']
    })


@app.route('/api/assessments/<int:assessment_id>', methods=['PUT'])
@token_required
@instructor_required
def update_assessment(current_user, assessment_id):
    data = request.json
    title = data.get('title')
    assessment_type = data.get('type')  
    questions = data.get('questions')

    update_fields = {}
    if title is not None:
        update_fields['title'] = title
    if assessment_type is not None:
        if assessment_type not in ['quiz', 'test']:
            return jsonify({'message': 'Invalid assessment type'}), 400
        update_fields['type'] = assessment_type
    if questions is not None:
        update_fields['questions'] = questions

    if not update_fields:
        return jsonify({'message': 'No data provided for update'}), 400

    result = mongo.db.assessments.update_one({'assessmentId': assessment_id}, {'$set': update_fields})
    if result.matched_count == 0:
        return jsonify({'message': 'Assessment not found or you are not the instructor'}), 404

    return jsonify({'message': 'Assessment updated'})


@app.route('/api/assessments/<int:assessment_id>', methods=['DELETE'])
@token_required
@instructor_required
def delete_assessment(current_user, assessment_id):
    result = mongo.db.assessments.delete_one({'assessmentId': assessment_id})
    if result.deleted_count == 0:
        return jsonify({'message': 'Assessment not found or you are not the instructor'}), 404

    return jsonify({'message': 'Assessment deleted'})

@app.route('/api/student_assessments', methods=['POST'])
@token_required
@student_required
def submit_assessment(current_user):
    data = request.json
    assessment_id = data.get('assessmentId')
    course_id = data.get('courseId')
    answers = data.get('answers')

    if not assessment_id or not course_id or not answers:
        return jsonify({'message': 'Assessment ID, course ID, and answers are required'}), 400

   
    score = 100.0

    result = mongo.db.student_assessments.insert_one({
        'studentId': current_user['userId'],
        'assessmentId': assessment_id,
        'courseId': course_id,
        'answers': answers,
        'score': score,
        'completionDate': datetime.datetime.utcnow()
    })

    return jsonify({'message': 'Assessment submitted successfully', 'score': score, 'completionDate': datetime.datetime.utcnow()}), 201


@app.route('/api/student_assessments/<int:assessment_id>', methods=['GET'])
@token_required
@student_required
def get_student_assessment(current_user, assessment_id):
    assessment = mongo.db.student_assessments.find_one({
        'studentId': current_user['userId'],
        'assessmentId': assessment_id
    })
    if not assessment:
        return jsonify({'message': 'Assessment not found'}), 404

    return jsonify(assessment)



from bson import ObjectId

def serialize_document(doc):
    """Convert MongoDB document to a serializable dictionary."""
    if isinstance(doc, ObjectId):
        return str(doc)
    elif isinstance(doc, dict):
        return {k: serialize_document(v) for k, v in doc.items()}
    elif isinstance(doc, list):
        return [serialize_document(item) for item in doc]
    return doc



@app.route('/api/student_assessments', methods=['GET'])
@token_required
@student_required
def get_all_student_assessments(current_user):
    assessments_cursor = mongo.db.student_assessments.find({'studentId': current_user['userId']})
    results = []
    for assessment in assessments_cursor:
        
        results.append(serialize_document(assessment))

    return jsonify(results)


@app.route('/api/payments', methods=['POST'])
@token_required
@student_required
def create_payment(current_user):
    data = request.json
    course_id = data.get('courseId')
    amount = data.get('amount')
    status = data.get('status', 'pending')  

    if not course_id or amount is None:
        return jsonify({'message': 'Course ID and amount are required'}), 400

    try:
        course_id = int(course_id)  
        amount = float(amount) 
    except ValueError:
        return jsonify({'message': 'Invalid course ID or amount format'}), 400

    course = mongo.db.courses.find_one({'courseId': course_id})
    if not course:
        return jsonify({'message': 'Course not found'}), 404

    payment_id = get_next_id('payment_id')  

    result = mongo.db.payments.insert_one({
        'paymentId': payment_id,
        'userId': current_user['userId'],
        'courseId': course_id,
        'amount': amount,
        'paymentDate': datetime.datetime.utcnow(),
        'status': status
    })

    return jsonify({'paymentId': payment_id, 'message': 'Payment created'}), 201


@app.route('/api/payments/<int:payment_id>', methods=['GET'])
@token_required
def read_payment(payment_id):
    payment = mongo.db.payments.find_one({'paymentId': payment_id})
    if not payment:
        return jsonify({'message': 'Payment not found'}), 404

    return jsonify({
        'paymentId': payment['paymentId'],
        'userId': payment['userId'],
        'courseId': payment['courseId'],
        'amount': payment['amount'],
        'paymentDate': payment['paymentDate'],
        'status': payment['status']
    })


@app.route('/api/payments/<int:payment_id>', methods=['PUT'])
@token_required
@student_required
def update_payment(current_user, payment_id):
    data = request.json
    amount = data.get('amount')
    status = data.get('status')

    update_fields = {}
    if amount is not None:
        try:
            update_fields['amount'] = float(amount)
        except ValueError:
            return jsonify({'message': 'Invalid amount format'}), 400
    if status is not None:
        if status not in ['completed', 'pending']:
            return jsonify({'message': 'Invalid payment status'}), 400
        update_fields['status'] = status

    if not update_fields:
        return jsonify({'message': 'No data provided for update'}), 400

    result = mongo.db.payments.update_one({'paymentId': payment_id, 'userId': current_user['userId']}, {'$set': update_fields})
    if result.matched_count == 0:
        return jsonify({'message': 'Payment not found or you are not authorized to update this payment'}), 404

    return jsonify({'message': 'Payment updated'})


@app.route('/api/payments/<int:payment_id>', methods=['DELETE'])
@token_required
@student_required
def delete_payment(current_user, payment_id):
    result = mongo.db.payments.delete_one({'paymentId': payment_id, 'userId': current_user['userId']})
    if result.deleted_count == 0:
        return jsonify({'message': 'Payment not found or you are not authorized to delete this payment'}), 404

    return jsonify({'message': 'Payment deleted'})


@app.route('/api/payments', methods=['GET'])
@token_required
@student_required
def get_all_payments(current_user):
    payments_cursor = mongo.db.payments.find({'userId': current_user['userId']})
    results = []
    for payment in payments_cursor:
        
        results.append(serialize_document(payment))

    return jsonify(results)




if __name__ == '__main__':
    app.run(debug=True, port=7003)








