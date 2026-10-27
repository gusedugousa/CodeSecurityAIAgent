resource "aws_s3_bucket" "data" {
  bucket = "example-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "default" {
  identifier        = "sample-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  username          = "admin"
  password          = "hardcoded-password-123"
  storage_encrypted = false
  publicly_accessible = true
}
