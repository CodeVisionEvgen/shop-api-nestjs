import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  Id: number;

  @Column({
    nullable: false,
  })
  FirstName: string;

  @Column({
    nullable: true,
  })
  LastName: string;
  @Column({
    nullable: false,
  })
  Email: string;

  @Column({
    nullable: true,
  })
  Password: string;

  @Column({
    nullable: false,
  })
  Provider: string;
}
