from flask import Flask, render_template, request, redirect, flash,url_for,session, jsonify, Response, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy.types import Numeric
from decimal import Decimal, InvalidOperation

import csv
from io import StringIO

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///banking_system.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = secrets.token_hex(16)
db = SQLAlchemy(app)


# Define the Customers table
class Customer(db.Model):
    customerID = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    address = db.Column(db.String(255))
    # City = db.Column(db.String(100))
    # State = db.Column(db.String(100))
    # ZipCode = db.Column(db.String(10))
    password = db.Column(db.String(255), nullable=False)
    createdAt = db.Column(db.DateTime, default=datetime.utcnow)
    accounts = db.relationship('Account', backref='customer', lazy=True)

# Define the Accounts table
class Account(db.Model):
    accountID = db.Column(db.Integer, primary_key=True)
    customerID = db.Column(db.Integer, db.ForeignKey('customer.customerID'), nullable=False)
    bank = db.Column(db.String(250), nullable=False)
    upiID = db.Column(db.String(150), nullable=False)
    pin = db.Column(db.String(255), nullable=False)    
    accountType = db.Column(db.String(50))
    balance = db.Column(db.Numeric(15, 2), nullable=False, default=Decimal('500.00'))
    createdAt = db.Column(db.DateTime, default=datetime.utcnow)

# # Define the Transactions table
class Transaction(db.Model):
    transactionID = db.Column(db.Integer, primary_key=True)
    accountID = db.Column(db.Integer, db.ForeignKey('account.accountID'), nullable=False)
    # transactionType = db.Column(db.String(50))
    s_upiId = db.Column(db.String(150), nullable=False)
    r_upiId = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Numeric(15, 2))
    transactionDate = db.Column(db.DateTime, default=datetime.utcnow)
    balance = db.Column(db.Numeric(15, 2), nullable=False)
    # Description = db.Column(db.String(255))

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        cname = request.form['cname']
        dob_str = request.form['dob']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        password = request.form['password']
        cpassword = request.form['cpassword']
        
        check_email = Customer.query.filter_by(email=email).first()
        check_phone = Customer.query.filter_by(phone=phone).first()
        
        if check_email or check_phone:  # Use 'or' instead of 'and'
            flash('Email or phone already exists', 'danger')
            return redirect(url_for('signup'))
            
        if password != cpassword:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()  # Convert string to date object
            new_user = Customer(name=cname, dob=dob, email=email, phone=phone, address=address, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error creating user: ' + str(e), 'danger')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = Customer.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.customerID
            session['email'] = user.email
            # flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    # flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/createacc', methods=['GET', 'POST'])
def createAcc():
    
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    
    if request.method == 'POST':
        bank = request.form['bank']
        upiID = request.form['upi']
        pin = request.form['pin']
        account_type = request.form['account_type']
        
        # Fetch customer based on email
        customer = Customer.query.filter_by(customerID=session['user_id']).first()
        
        if customer:
            # Validate PIN
            if not (pin.isdigit() and len(pin) == 4):
                flash('PIN must be a 4-digit number', 'danger')
                return redirect(url_for('createAcc'))
            
            check_upi = Account.query.filter_by(upiID=upiID).first()
            check_bank = Account.query.filter_by(customerID=session['user_id'], bank=bank).first()
            
            if check_bank:
                flash('You already have account in this bank!', 'danger')
                return redirect(url_for('createAcc'))
            
            if check_upi:
                flash('UPI Id Already Exist!', 'danger')
                return redirect(url_for('createAcc'))
            
            # Hash the PIN
            hashed_pin = generate_password_hash(pin, method='pbkdf2:sha256')
            
            # Create a new account
            new_account = Account(customerID=customer.customerID, bank=bank, upiID=upiID, pin=hashed_pin, accountType=account_type)
            try:
                db.session.add(new_account)
                db.session.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('createAcc'))
            except Exception as e:
                flash('Error creating account: ' + str(e), 'danger')
                return redirect(url_for('createAcc'))
        else:
            flash('Customer not found', 'danger')
            return redirect(url_for('createAcc'))
    
    customer = Customer.query.filter_by(customerID=session['user_id']).first()
    email = customer.email if customer else "Customer"
    phone = customer.phone if customer else "Customer"
    
    return render_template('create_acc.html', email=email, phone=phone)

@app.route('/get_upi_id', methods=['POST'])
def get_upi_id():
    if 'user_id' not in session:
        return {'upi_id': ''}  # Return an empty response if the user is not logged in
    bank = request.json['bank']
    account = Account.query.filter_by(bank=bank, customerID=session['user_id']).first()
    if account:
        return {'upi_id': account.upiID}
    return {'upi_id': ''}

@app.route('/get_receiver_name', methods=['POST'])
def get_receiver_name():
    if 'user_id' not in session:
        return jsonify({'receiver_name': ''})  # Return an empty response if the user is not logged in
    
    upi_id = request.json.get('upi_id')
    account = Account.query.filter_by(upiID=upi_id).first()
    
    if account:
        customer = Customer.query.filter_by(customerID=account.customerID).first()
        if customer:
            return jsonify({'receiver_name': customer.name})
    # flash('Enter valid UPI', 'danger')
    return jsonify({'receiver_name': ''})

@app.route('/get_receiver_bank', methods=['POST'])
def get_receiver_bank():
    if 'user_id' not in session:
        return jsonify({'receiver_bank': ''})  # Return an empty response if the user is not logged in
    
    upi_id = request.json.get('upi_id')
    account = Account.query.filter_by(upiID=upi_id).first()
    
    if account:
        return jsonify({'receiver_bank': account.bank})
    # flash('Enter valid UPI', 'danger')
    return jsonify({'receiver_bank': ''})

@app.route('/transaction', methods=['GET', 'POST'])
def transaction():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    customer = Customer.query.filter_by(customerID=session['user_id']).first()
    
    if request.method == 'POST':
        sender_bank = request.form['bank']
        sender_upi = request.form['upi']
        receiver_upi = request.form['r_upi']
        amount = request.form['r_amount']
        pin = request.form['pin']
        
        # Fetch sender account details
        sender_account = Account.query.filter_by(bank=sender_bank, upiID=sender_upi, customerID=customer.customerID).first()
        
        if not sender_account:
            flash('Sender account not found', 'danger')
            return redirect(url_for('transaction'))
        
        # Validate PIN
        if not check_password_hash(sender_account.pin, pin):
            flash('Invalid PIN', 'danger')
            return redirect(url_for('transaction'))
        
        # Validate amount
        try:
            amount = Decimal(amount)
        except InvalidOperation:
            flash('Invalid amount', 'danger')
            return redirect(url_for('transaction'))

        if amount <= 0:
            flash('Invalid amount', 'danger')
            return redirect(url_for('transaction'))
        
        if sender_account.balance < amount:
            flash('Insufficient balance', 'danger')
            return redirect(url_for('transaction'))
        
        # Fetch receiver account details
        receiver_account = Account.query.filter_by(upiID=receiver_upi).first()
        
        if not receiver_account:
            flash('Receiver account not found', 'danger')
            return redirect(url_for('transaction'))
        
        # Perform the transaction
        try:
            sender_account.balance -= amount
            receiver_account.balance += amount
            
            # Create transaction record
            new_transaction = Transaction(accountID=sender_account.accountID, r_upiId=receiver_upi,s_upiId=sender_upi, amount=amount, balance=sender_account.balance)
            db.session.add(new_transaction)
            
            db.session.commit()
            flash('Transaction successful!', 'success')
            return redirect(url_for('transaction'))
        except Exception as e:
            db.session.rollback()
            flash('Transaction failed: ' + str(e), 'danger')
            return redirect(url_for('transaction'))
    
    # Fetch all banks where the customer has accounts
    customer_accounts = Account.query.filter_by(customerID=customer.customerID).all()
    banks = list(set(account.bank for account in customer_accounts))
    
    email = customer.email if customer else "Customer"
    phone = customer.phone if customer else "Customer"
    
    return render_template('transaction.html', banks=banks, email=email, phone=phone)

@app.route('/bank_details')
def bankDetails():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    allBank = Account.query.filter_by(customerID=session['user_id']).all()
    
    return render_template('bankdetails.html', allBank=allBank)


@app.route('/transaction_history')
def transHistory():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    customer_accounts = Account.query.filter_by(customerID=session['user_id']).all()
    account_ids = [account.accountID for account in customer_accounts]
    
    allTransactions = Transaction.query.filter(Transaction.accountID.in_(account_ids)).all()
    
    return render_template('transaction_history.html', allTransaction=allTransactions)


@app.route('/export_csv')
def export_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    customer = Customer.query.get(session['user_id'])
    account_ids = [account.accountID for account in customer.accounts]
    
    all_transactions = Transaction.query.filter(Transaction.accountID.in_(account_ids)).all()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Transaction ID', 'Sender UPI', 'Receiver UPI', 'Amount Transferred', 'Balance', 'Transaction Date'])
    
    for transaction in all_transactions:
        writer.writerow([
            transaction.transactionID, 
            transaction.s_upiId, 
            transaction.r_upiId, 
            transaction.amount, 
            transaction.balance, 
            transaction.transactionDate.strftime('%d-%m-%Y')
        ])
    
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=transaction_history.csv"
    response.headers["Content-type"] = "text/csv"
    return response

if __name__ == '__main__':
    app.run(debug=True)
